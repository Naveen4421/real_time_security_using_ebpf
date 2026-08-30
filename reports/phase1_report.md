# Phase 1 Implementation Report: Data Collection & Observation

This report documents the architectural transition and implementation details for **Phase 1: Data Collection & Observation**.

---

## 1. Before vs. After System Comparison

| System Dimension | Before (Legacy Rule-Based Simulator) | After Phase 1 (ML-Based Pipeline) |
| :--- | :--- | :--- |
| **Detection Method** | Rule-Based checks on individual syscall events. | **Sliding Window Analysis** aggregating multiple metrics into feature spaces. |
| **Language & Engine** | Express.js backend simulator and Falco rules. | **Python 3.12 Engine** parsing and computing telemetry statistics. |
| **Kubernetes Enrichment** | Static pod names matching hardcoded patterns. | **Dynamic Kubernetes API query** via `kubectl` JSON inspection. |
| **Feature Extraction** | None. Only raw alert fields forwarded. | **17 Statistical Features** calculated dynamically over sliding windows (CPU, Mem, process depth, sensitive files). |
| **Telemetry Stream** | Webhook fan-out to Falcosidekick and Talon. | **Continuous cloud stream simulation** feeding `cloud_stream.json`. |
| **Documentation Scope** | General Falco/Sidekick setup guidelines. | **Unified 8-Phase Roadmap** and pipeline specifications (`README.md`, `GEMINI.md`). |

---

## 2. Implementations Completed in Phase 1

1. **Python Data Collection Module (`ml_pipeline/data_collection.py`):**
   *   `parse_bpf_event`: Parses raw kernel probe outputs into key-value structures.
   -   `enrich_with_k8s_metadata`: Integrates with the live Kubernetes cluster by querying pod specs matching container IDs.
   *   `add_to_sliding_window`: Thread-safe, memory-bounded deque aggregation representing a 10s node execution window.
   -   `compute_window_stats`: Computes process rates, file rate, memory averages, and network connections.
   *   `stream_to_cloud`: Streams outputs to a simulated cloud control plane log.

2. **Validation Runner (`ml_pipeline/test_phase1.py`):**
   *   A test runner simulating active multi-syscall inputs (bash shells, openat, shadow reads).
   -   Verifies sliding window increments, averages, and persistent output generation.

---

## 3. Transition Plan: Moving to Phase 2
With Phase 1 completed, the statistical telemetry is successfully streamed to the control plane. In the next phase:
*   **Phase 2: ML Training & Model Generation** will consume the accumulated window stats to engineer features and train **Isolation Forest** and **Autoencoder** models for anomaly detection.
