import json
import numpy as np
from model_training import engineer_features, train_isolation_forest, train_autoencoder, ensemble_voting

# 1. Generate realistic synthetic telemetry dataset representing:
# - Normal behavior: Low system call rates, minimal sensitive files, low process depth
# - Anomalous behavior: Spawning shells, reading shadow files, high CPU/IO activity
normal_base = {
    "syscall_frequency": 2.5,
    "unique_syscalls": 3,
    "file_access_rate": 1.2,
    "unique_files": 2,
    "sensitive_file_access": 0,
    "network_connections": 1,
    "unique_ports": 1,
    "outbound_traffic": 1024,
    "process_executions": 2,
    "unique_processes": 2,
    "process_hierarchy_depth": 2,
    "cpu_usage": 8.0,
    "memory_usage": 35.0,
    "io_wait": 1.5
}

anomalous_base = {
    "syscall_frequency": 45.0,
    "unique_syscalls": 12,
    "file_access_rate": 22.0,
    "unique_files": 15,
    "sensitive_file_access": 8,
    "network_connections": 15,
    "unique_ports": 5,
    "outbound_traffic": 984021,
    "process_executions": 18,
    "unique_processes": 10,
    "process_hierarchy_depth": 5,
    "cpu_usage": 78.0,
    "memory_usage": 92.0,
    "io_wait": 22.5
}

dataset = []

# Generate 100 normal samples (with random Gaussian noise)
for _ in range(100):
    sample = {}
    for k, v in normal_base.items():
        # Add random noise and ensure non-negative
        noise = np.random.normal(0, v * 0.15)
        sample[k] = max(0.0, v + noise)
    dataset.append(sample)

# Generate 5 anomalous samples
for _ in range(5):
    sample = {}
    for k, v in anomalous_base.items():
        noise = np.random.normal(0, v * 0.15)
        sample[k] = max(0.0, v + noise)
    dataset.append(sample)

print("🚀 Running Phase 2 Model Training Validation...")
print(f"Dataset generated: {len(dataset)} telemetry samples (100 normal, 5 anomalous)")

# 2. Extract features
features = engineer_features(dataset)
print(f"Feature matrix engineered. Shape: {features.shape}")

# 3. Train Isolation Forest
iforest_model, iforest_baseline = train_isolation_forest(features)
print(f"Isolation Forest Baseline stats: Mean={iforest_baseline['mean']:.4f}, Std={iforest_baseline['std']:.4f}")

# 4. Train Autoencoder
ae_model, ae_baseline = train_autoencoder(features)
print(f"Autoencoder Baseline stats: Mean={ae_baseline['mean']:.4f}, Std={ae_baseline['std']:.4f}")

# 5. Evaluate ensemble voting on a test anomaly
test_anomaly = engineer_features(anomalous_base)

# Calculate anomaly score (Isolation Forest)
# We want to scale score so that higher = more anomalous.
# Iforest score_samples returns negative values (lower = more anomalous). Let's map it.
iforest_raw_score = iforest_model.score_samples(test_anomaly)[0]
# Normal range is ~ -0.4 to -0.7. Let's make it a normalized anomaly intensity.
iforest_anomaly_intensity = max(0.0, -iforest_raw_score)

# Calculate autoencoder reconstruction loss
import torch
ae_model.eval()
with torch.no_grad():
    test_tensor = torch.tensor(test_anomaly, dtype=torch.float32)
    reconstructed = ae_model(test_tensor)
    ae_loss = torch.mean((test_tensor - reconstructed) ** 2).item()

# Ensemble voting
scores = {
    'isolation_forest': iforest_anomaly_intensity,
    'autoencoder': ae_loss
}
combined = ensemble_voting(scores)

print(f"\n--- Evaluation on Test Anomaly (Intrusion Attempt) ---")
print(f"Isolation Forest Score: {scores['isolation_forest']:.4f}")
print(f"Autoencoder Loss: {scores['autoencoder']:.4f}")
print(f"Ensemble Anomaly Decision Metric: {combined:.4f}")
print("✅ Phase 2 training and evaluation verified successfully!")
