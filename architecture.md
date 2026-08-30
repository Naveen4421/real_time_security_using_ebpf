
# Architectural Analysis: Current Status vs. Target Architecture

This document provides a detailed breakdown of the features currently implemented in the **eBPF Security Simulator** project compared to the target enterprise architecture illustrated in the diagram above.

---

## 1. Present Project Implementation (What is Completed)

The present project implements a fully functional local simulator showcasing multi-layered runtime threat detection and active response:

### A. Kernel-Space Syscall Interception (Layers 5a & 6)
*   **eBPF Probe Integration:** We utilize **Falco's modern eBPF probe** at the kernel boundary to intercept system calls (such as `openat` and `execve`).
*   **Syscall Rules:** Custom rules (`configs/falco_rules.local.yaml` and `configs/falco_rules.k8s.yaml`) detect specific patterns (e.g., shell spawns or file access in designated folders like `/bin/hack` or `/etc/shadow`).

### B. Response Execution & Mitigation (Layer 7)
*   **Cluster-Level Mitigation (Falco Talon):** Falco Talon runs as a persistent service, monitoring Falco alerts via Falcosidekick. When rules match, it contacts the Kubernetes API server to terminate offending pods (`kubernetes:terminate`).
*   **Application-Level Self-Protection (RASP):** The Express backend contains active defense handlers:
    *   **Lockdown Containment:** Rate-limits and blocks sensitive route paths (returns `403 Forbidden`) when threat thresholds are exceeded.
    *   **Self-Healing Quarantine:** Periodically detects unauthorized file writes (such as `/bin/hack`) and automatically deletes/quarantines them after 1 second.
*   **Mitigation Webhooks:** Both Falco alerts and Falco Talon actions send webhook payloads back to `/api/security/events` and `/api/talon/events` respectively, completing the notification loop.

### C. Data Collection & Monitoring (Layers 1 & 8)
*   **Observability Pipeline:** Falcosidekick collects Falco alerts, updating Prometheus counters and generating logs. Loki and Promtail are configured in Docker Compose for log aggregation.
*   **Operator Dashboard:** A glassmorphic Vanilla Web UI displays active threat status, containment countdowns, and a real-time incident feed of kernel, cluster, and application-level remediation logs.

---

## 2. What Remains to be Done (Future Scope)

To transition from the current simulation environment to the target enterprise architecture, the following areas must be built:

### A. Cloud Control Plane (Layers 1, 2, 3, & 4)
Currently, there is no centralized control plane. Everything runs locally in Minikube/Docker. To match the target:
*   **Data Aggregation Pipeline:** Implement a scalable streaming ingest pipeline using **Kafka** for raw alert ingestion, **Flink** for stream processing, and **Spark** for batch analytics, archiving data to **S3 storage**.
*   **Central ML Training Pipeline:** Build automated pipelines to train anomaly detection models using algorithms like **Isolation Forest** and **Autoencoders** to discover unknown or zero-day attack patterns (moving away from purely signature/rule-based detection).
*   **Model Registry:** Configure **MLflow** for model tracking, version control, and executing rolling/Canary deployments of threat detection models.
*   **Policy Engine:** Create a centralized dashboard to define tenant-level security policies, classify incident severities, and generate custom eBPF verification specifications.

### B. Customer Kubernetes Cluster: DaemonSet Agent (Layer 5)
Currently, services run as systemd daemons on the host. The architecture calls for a unified DaemonSet:
*   **DaemonSet Packaging:** Package the agent (probe manager, data collector, inference engine) as a Kubernetes **DaemonSet** so it spins up automatically on every cluster node.
*   **Edge ML Inference Engine (5c):** Port the trained Isolation Forest and Autoencoder models to the Edge Agent to perform real-time, low-latency ML anomaly detection on the node itself.
*   **Dynamic eBPF Code Generator & Loader (5d):** Implement dynamic compilation of eBPF programs on the agent (via Clang/bpftool) to compile and load filters on-the-fly based on policies pushed from the Cloud Control Plane.
*   **Extended Hooks (5a):** Expand eBPF hooking capabilities beyond kprobes/tracepoints to network interfaces using **XDP (eXpress Data Path)** and **TC (Traffic Control)** for kernel-level network packet filtering.

### C. Feedback Loop (Layer 8)
*   **Model Retraining:** Create an automated loop where operators' feedback on false positives/negatives is collected, shipped to S3, and used to retrain the control plane's ML models, pushing updated parameters back to the edge agents.
