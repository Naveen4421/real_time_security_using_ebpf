import os
import sys
import json
import time

try:
    from ml_pipeline.model_inference import deploy_model_to_edge, edge_inference
    from ml_pipeline.policy_generation import AnomalyClassifier, PolicyLifecycleManager, OUTPUT_POLICIES_DIR
    from ml_pipeline.execution_layer import Phase5ExecutionEngine
    from ml_pipeline.observability import (
        K8sIntegrationManager,
        PrometheusObservabilityExporter,
        UnifiedLoggingPipeline,
        Phase7ObservabilityEngine,
        GRAFANA_DASHBOARDS_DIR,
        PROMETHEUS_ALERTS_PATH,
        UNIFIED_AUDIT_PATH
    )
except ImportError:
    from model_inference import deploy_model_to_edge, edge_inference
    from policy_generation import AnomalyClassifier, PolicyLifecycleManager, OUTPUT_POLICIES_DIR
    from execution_layer import Phase5ExecutionEngine
    from observability import (
        K8sIntegrationManager,
        PrometheusObservabilityExporter,
        UnifiedLoggingPipeline,
        Phase7ObservabilityEngine,
        GRAFANA_DASHBOARDS_DIR,
        PROMETHEUS_ALERTS_PATH,
        UNIFIED_AUDIT_PATH
    )

mock_telemetry_window = [
    {
        "syscall_frequency": 70.0,
        "unique_syscalls": 19,
        "file_access_rate": 35.0,
        "unique_files": 16,
        "sensitive_file_access": 14,
        "network_connections": 25,
        "unique_ports": 9,
        "outbound_traffic": 3200000,
        "process_executions": 28,
        "unique_processes": 15,
        "process_hierarchy_depth": 7,
        "cpu_usage": 89.0,
        "memory_usage": 86.0,
        "io_wait": 38.0
    }
]

def run_phase7_tests():
    print("🚀 Running Phase 7 Integration & Observability Layer Validation...\n")
    start_time = time.time()

    # 1. Pipeline Prerequisites (Phase 3 -> Phase 4 -> Phase 5)
    print("1️⃣ Running Pipeline Prerequisites...")
    deploy_model_to_edge()
    container_id = "k8s-pod-container-88"
    inference_result = edge_inference(container_id, mock_telemetry_window)
    classification = AnomalyClassifier.classify_anomaly(inference_result, mock_telemetry_window)
    
    lifecycle_mgr = PolicyLifecycleManager(storage_dir=OUTPUT_POLICIES_DIR)
    policy_meta = lifecycle_mgr.create_and_deploy(classification)
    print("✅ Prerequisites Prepared.")

    # 2. Test Component A: K8s Metadata Enrichment
    print("\n2️⃣ Testing Kubernetes Pod Discovery & Container Metadata Enrichment...")
    k8s_mgr = K8sIntegrationManager()
    k8s_meta = k8s_mgr.discover_and_enrich(container_id)
    
    assert k8s_meta['container_id'] == container_id, "Container ID mismatch"
    assert k8s_meta['pod_name'], "Pod name missing"
    assert k8s_meta['namespace'], "Namespace missing"
    assert k8s_meta['rbac_verified'], "RBAC verification failed"
    print(f"✅ K8s Metadata Enrichment verified: Pod='{k8s_meta['pod_name']}', NS='{k8s_meta['namespace']}', ServiceMesh='{k8s_meta['service_mesh']}'")

    # 3. Test Component B: Prometheus Exporter & Grafana Dashboards
    print("\n3️⃣ Testing Prometheus Metrics Exporter & Grafana Dashboard Rendering...")
    exporter = PrometheusObservabilityExporter()
    exporter.record_anomaly('CRITICAL', 'SENSITIVE_FILE_ACCESS')
    exporter.record_policy_gen('ebpf')
    exporter.record_response_action('kubernetes:terminate')
    exporter.record_latency(14.8)
    
    prom_stream = exporter.export_prometheus_format()
    assert "ebpf_ml_anomalies_detected_total" in prom_stream, "Prometheus metrics export failed"
    assert "ebpf_ml_model_accuracy_ratio" in prom_stream, "Model accuracy metric missing"
    
    dash_path = exporter.generate_grafana_dashboard_json()
    assert os.path.exists(dash_path), "Grafana dashboard manifest missing"
    
    alerts_path = exporter.generate_prometheus_alerts_yml()
    assert os.path.exists(alerts_path), "Prometheus alerts rules file missing"
    print("✅ Prometheus Exporter, Grafana Dashboards, and Alerts verified successfully.")

    # 4. Test Component C: Unified JSON Logging & Audit Pipeline
    print("\n4️⃣ Testing Unified JSON Audit Logging Pipeline...")
    logger = UnifiedLoggingPipeline(audit_path=UNIFIED_AUDIT_PATH)
    audit_rec = logger.log_event("TEST_ANOMALY_EVENT", {"container_id": container_id, "status": "CONTAINED"})
    
    assert os.path.exists(UNIFIED_AUDIT_PATH), "Unified audit log missing"
    with open(UNIFIED_AUDIT_PATH, "r") as f:
        log_data = json.load(f)
        assert len(log_data) > 0, "Audit log file empty"
    print("✅ Unified Logging & Audit Pipeline verified successfully.")

    # 5. Test Master Phase 7 Observability Engine
    print("\n5️⃣ Testing Master Phase 7 Observability Engine Pipeline...")
    master_engine = Phase7ObservabilityEngine()
    result = master_engine.process_observability_pipeline(container_id, inference_result, policy_meta)
    
    assert result['grafana_dashboard'] and os.path.exists(result['grafana_dashboard'])
    assert result['prometheus_alerts'] and os.path.exists(result['prometheus_alerts'])
    assert result['prom_metrics_bytes'] > 0

    elapsed_ms = (time.time() - start_time) * 1000
    print(f"\n🎉 Phase 7 Integration & Observability Layer fully verified in {round(elapsed_ms, 2)} ms!")

if __name__ == "__main__":
    run_phase7_tests()
