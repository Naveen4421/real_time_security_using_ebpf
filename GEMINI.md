# Project Guidelines & Architecture Index (GEMINI.md)

Welcome to the **eBPF ML-Based Anomaly Detection & Active Response System** workspace. This document serves as the team-shared engineering guidelines, architectural index, and operational reference for this repository.

---

## 1. Project Architecture

We are replacing the static rule-based detection engine with an 8-phase dynamic machine-learning security pipeline.

```
       +---------------------------------------------+
       |             CLOUD CONTROL PLANE             |
       |  - ML Training Pipeline (IForest, AE)       |
       |  - Policy Engine & Code Generator           |
       +----------------------▲----------------------+
                              │
               Stream Stats   │   Push Edge Models &
               (JSON Webhook) │   Dynamic eBPF Probes
                              │
       +----------------------▼----------------------+
       |          EDGE AGENT (DaemonSet)             |
       |  - Phase 1: data_collection.py              |
       |  - Phase 3: Real-time Edge Inference        |
       |  - Phase 5: Dynamic clang/bpftool Loader    |
       +---------------------------------------------+
```

---

## 2. Phase 1 Technical Specification

### A. Ingested BPF Event Spec
Raw events from the BPF probes must contain the following keys:
*   `timestamp`: ISO-8601 UTC string.
*   `container_id`: The Docker/container runtime hash.
*   `syscall`: Name of the system call.
*   `process`: Object containing `name`, `pid`, and hierarchy `depth`.
*   `file`: The target file path for IO operations (optional).
*   `resource_usage`: Object with `cpu`, `memory`, and `io` values.

### B. Statistical Feature Space
The data collection pipeline aggregates events into a sliding window and produces the following features for ML training:
*   `syscall_frequency`: Frequency of calls/sec.
*   `unique_syscalls`: Number of unique syscalls observed in the window.
*   `file_access_rate`: Frequency of file opens/sec.
*   `sensitive_file_access`: Count of matches against restricted paths.
*   `unique_processes`: Unique executing command names.
*   `process_hierarchy_depth`: Maximum depth of process tree.
*   `cpu_usage` / `memory_usage` / `io_wait`: Rolling averages.

---

## 3. Phase 2 Technical Specification

### A. Feature Matrix Vectorization
All computed window stats must be engineered into a 14-dimensional floating-point array aligned with `FEATURE_KEYS`:
`[syscall_frequency, unique_syscalls, file_access_rate, unique_files, sensitive_file_access, network_connections, unique_ports, outbound_traffic, process_executions, unique_processes, process_hierarchy_depth, cpu_usage, memory_usage, io_wait]`

### B. Isolation Forest Hyperparameters
*   `contamination = 0.05`
*   `n_estimators = 100`
*   `random_state = 42`

### C. Autoencoder PyTorch Architecture
*   **Layer 1 (Input):** `Linear(14, 32) -> ReLU`
*   **Layer 2 (Encoder):** `Linear(32, 16) -> ReLU`
*   **Layer 3 (Bottleneck):** `Linear(16, 4)`
*   **Layer 4 (Decoder):** `Linear(4, 16) -> ReLU`
*   **Layer 5 (Output reconstruction):** `Linear(16, 32) -> ReLU -> Linear(32, 14)`
*   **Loss Metric:** Mean Squared Error (MSE) reconstruction loss.

---

## 4. Phase 3 Technical Specification

### A. Edge Deployment Payload
*   **Deployment package:** Contains pickled Isolation Forest, state dict of PyTorch Autoencoder, and baseline statistical thresholds.
*   **Edge Loading Interface:** Edge Agent loads weights and builds locally running inference objects.

### B. Anomaly Scoring Fuses
*   `iforest_weight = 0.5`
*   `autoencoder_weight = 0.5`
*   Combined anomaly metric: `(iforest_anomaly_score * 0.5) + (ae_reconstruction_loss * 0.5)`.

### C. Threat Classification Bounds
Classification rules for container security actions:
*   `CRITICAL`: Anomaly score is in the 99th percentile of baseline training data or Isolation Forest outlier score > 0.8.
*   `HIGH`: Anomaly score is in the 95th percentile or Isolation Forest score > 0.65.
*   `MEDIUM`: Anomaly score is in the 90th percentile or Isolation Forest score > 0.5.
*   `LOW`: Normal container telemetry.

---

## 5. Engineering & Contribution Rules

1. **State Preservation:** The sliding windows and telemetry storage must reside under `ml_pipeline/` for Phase 1. Do not use external database dependencies at this stage.
2. **Kubernetes Interoperability:** Kubernetes queries via `kubectl` must implement dynamic error checking and fall back to safe mocks if running in environment boundaries.
3. **No-Bypass Policy:** All parsed inputs must be sanitized. Standard exceptions must be caught and logged cleanly.
4. **Validation:** Always execute local validation test runners (`python3 test_phase1.py`, `python3 test_phase2.py`, and `python3 test_phase3.py`) to confirm that code modifications do not break aggregates or model outputs.
5. **Model Storage:** All trained parameters and configurations must be saved inside `ml_pipeline/models/` using PyTorch serialization (`.pth`) and Pickling (`.pkl`).
