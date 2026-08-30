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

## 3. Engineering & Contribution Rules

1. **State Preservation:** The sliding windows and telemetry storage must reside under `ml_pipeline/` for Phase 1. Do not use external database dependencies at this stage.
2. **Kubernetes Interoperability:** Kubernetes queries via `kubectl` must implement dynamic error checking and fall back to safe mocks if running in environment boundaries.
3. **No-Bypass Policy:** All parsed inputs must be sanitized. Standard exceptions must be caught and logged cleanly.
4. **Validation:** Always execute the validation test runner (`python3 test_phase1.py`) locally to confirm that code modifications do not break window aggregates.
