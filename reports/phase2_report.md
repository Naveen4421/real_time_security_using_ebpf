# Phase 2 Implementation Report: ML Training & Model Generation

This report documents the architectural transition and implementation details for **Phase 2: ML Training & Model Generation**.

---

## 1. Before vs. After System Comparison

| System Dimension | Before Phase 2 | After Phase 2 (ML Training & Model Generation) |
| :--- | :--- | :--- |
| **Model Architectures** | None. Pure rule-based configurations (Falco). | **Dual ML Models**: Scikit-Learn **Isolation Forest** & PyTorch **Autoencoder** Neural Network. |
| **Feature Extraction** | Basic window stats calculated but not vectorized. | **Feature Engineering Engine** converting raw JSON/dictionaries into a structured 14-dimensional mathematical matrix. |
| **Anomaly Scoring** | Binary threat rules (matched/unmatched). | **Continuous Anomaly Scoring** + Reconstruction Error baseline tracking. |
| **Model State Storage** | None. | **Model Serialization Store** saving `.pkl` (Isolation Forest) and `.pth` (PyTorch state_dict) weights under `ml_pipeline/models/`. |
| **Ensemble Logic** | None. | **Weighted Ensemble Voting** combining deep learning and clustering scores. |

---

## 2. Implementations Completed in Phase 2

1. **ML Training Module (`ml_pipeline/model_training.py`):**
   *   `engineer_features`: Maps the 14 statistical metrics into aligned, typed matrices.
   *   `train_isolation_forest`: Fits Isolation Forest to detect outlier metrics, computing standard deviation baseline scores.
   *   `Autoencoder (nn.Module)`: Implements a 5-layer linear deep bottleneck neural network (input size 14 -> 32 -> 16 -> 4 encoding -> 16 -> 32 -> 14 output).
   *   `train_autoencoder`: Performs gradient descent optimization (Adam, MSE) to train the Autoencoder and maps reconstruction baseline statistics.
   *   `ensemble_voting`: Fuses model scores using customizable weights.

2. **Validation and Baseline Runner (`ml_pipeline/test_phase2.py`):**
   *   Generates a training set (100 normal baseline telemetry samples, 5 intrusion anomaly samples).
   -   Trains both models concurrently and evaluates ensemble classification on test anomalies.

---

## 3. Transition Plan: Moving to Phase 3
Now that models are trained and saved under `ml_pipeline/models/`, we need:
*   **Phase 3: Model Deployment & Inference** to push these models down to edge containers, run real-time inference loop on the edge agent, and explore kernel-level inference translations.
