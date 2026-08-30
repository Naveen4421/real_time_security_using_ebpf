import json
from model_inference import deploy_model_to_edge, edge_inference, kernel_inference

# Mock normal event window (low rate, no sensitive files)
mock_normal_window = [
    {
        "syscall_frequency": 2.1,
        "unique_syscalls": 2,
        "file_access_rate": 0.8,
        "unique_files": 1,
        "sensitive_file_access": 0,
        "network_connections": 1,
        "unique_ports": 1,
        "outbound_traffic": 512,
        "process_executions": 1,
        "unique_processes": 1,
        "process_hierarchy_depth": 1,
        "cpu_usage": 3.0,
        "memory_usage": 30.0,
        "io_wait": 0.5
    }
]

# Mock highly anomalous event window (massive outbound traffic, shell spawns, sensitive files)
mock_anomalous_window = [
    {
        "syscall_frequency": 50.0,
        "unique_syscalls": 15,
        "file_access_rate": 25.0,
        "unique_files": 12,
        "sensitive_file_access": 9,
        "network_connections": 18,
        "unique_ports": 6,
        "outbound_traffic": 1502931,
        "process_executions": 20,
        "unique_processes": 11,
        "process_hierarchy_depth": 6,
        "cpu_usage": 85.0,
        "memory_usage": 95.0,
        "io_wait": 30.0
    }
]

print("🚀 Running Phase 3 Model Deployment & Inference Validation...\n")

# 1. Deploy models to edge
deployed = deploy_model_to_edge()
if not deployed:
    print("❌ Failed to deploy models to edge.")
    exit(1)

# 2. Run Edge Inference on normal behavior
print("\n--- Running Inference on Normal Telemetry Window ---")
normal_result = edge_inference("container-web-11", mock_normal_window)
print(json.dumps(normal_result, indent=2))

# 3. Run Edge Inference on anomalous behavior
print("\n--- Running Inference on Anomalous Telemetry Window ---")
anomaly_result = edge_inference("container-hack-22", mock_anomalous_window)
print(json.dumps(anomaly_result, indent=2))

# 4. Trigger Kernel-level Simulation
kernel_inference()

print("\n✅ Phase 3 edge deployment and inference verified successfully!")
