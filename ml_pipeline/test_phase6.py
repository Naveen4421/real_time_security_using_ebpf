import os
import sys
import json
import time

try:
    from ml_pipeline.model_inference import deploy_model_to_edge, edge_inference
    from ml_pipeline.policy_generation import AnomalyClassifier, PolicyLifecycleManager, OUTPUT_POLICIES_DIR
    from ml_pipeline.execution_layer import Phase5ExecutionEngine
    from ml_pipeline.feedback_learning import (
        FeedbackCollector,
        PerformanceImpactMonitor,
        ModelRetrainingPipeline,
        PolicyImprovementEngine,
        Phase6FeedbackEngine
    )
except ImportError:
    from model_inference import deploy_model_to_edge, edge_inference
    from policy_generation import AnomalyClassifier, PolicyLifecycleManager, OUTPUT_POLICIES_DIR
    from execution_layer import Phase5ExecutionEngine
    from feedback_learning import (
        FeedbackCollector,
        PerformanceImpactMonitor,
        ModelRetrainingPipeline,
        PolicyImprovementEngine,
        Phase6FeedbackEngine
    )

# Mock anomalous window
mock_anomalous_window = [
    {
        "syscall_frequency": 80.0,
        "unique_syscalls": 22,
        "file_access_rate": 50.0,
        "unique_files": 20,
        "sensitive_file_access": 16,
        "network_connections": 35,
        "unique_ports": 12,
        "outbound_traffic": 5000000,
        "process_executions": 35,
        "unique_processes": 18,
        "process_hierarchy_depth": 9,
        "cpu_usage": 98.0,
        "memory_usage": 92.0,
        "io_wait": 45.0
    }
]

def run_phase6_tests():
    print("🚀 Running Phase 6 Continuous Feedback & Learning Loop Validation...\n")
    start_time = time.time()

    # 1. Prerequisite Pipeline Execution (Phase 3 -> 4 -> 5)
    print("1️⃣ Running Pipeline Prerequisites (Phase 3 -> Phase 4 -> Phase 5)...")
    deploy_model_to_edge()
    container_id = "test-feedback-container-77"
    inference_result = edge_inference(container_id, mock_anomalous_window)
    classification = AnomalyClassifier.classify_anomaly(inference_result, mock_anomalous_window)
    
    lifecycle_mgr = PolicyLifecycleManager(storage_dir=OUTPUT_POLICIES_DIR)
    policy_meta = lifecycle_mgr.create_and_deploy(classification)
    
    exec_engine = Phase5ExecutionEngine()
    exec_engine.execute_phase5_pipeline(policy_meta)
    print("✅ Prerequisites Complete.")

    # 2. Test Component A: Feedback Collector
    print("\n2️⃣ Testing Feedback Collector (Incident Logging & Verification)...")
    collector = FeedbackCollector()
    inc_id = collector.log_incident(
        policy_meta['policy_id'],
        container_id,
        inference_result['score'],
        inference_result['severity'],
        mock_anomalous_window
    )
    assert inc_id, "Incident logging failed"

    record = collector.record_user_feedback(inc_id, "TRUE_POSITIVE", comments="Verified unauthorized file write")
    assert record['user_feedback'] == "TRUE_POSITIVE", "Feedback recording failed"
    
    stats = collector.get_feedback_statistics()
    assert stats['precision'] > 0 and stats['recall'] > 0, "Statistics calculation error"
    print(f"✅ Feedback Collector verified: Precision={stats['precision']}, Recall={stats['recall']}, F1={stats['f1_score']}")

    # 3. Test Component B: Performance & Impact Monitor
    print("\n3️⃣ Testing Performance & Impact Monitor (SLO/SLA Health Check)...")
    monitor = PerformanceImpactMonitor(target_latency_ms=50.0, min_precision=0.90)
    monitor.record_latency(18.5)
    monitor.record_latency(14.2)
    health = monitor.evaluate_system_health(stats)
    
    assert health['system_status'] in ["HEALTHY", "DEGRADED"], "System status check failed"
    assert health['latency_slo_met'], "Latency SLO check failed"
    assert health['resource_metrics']['cpu_overhead_percent'] < 1.0, "CPU overhead SLO exceeded"
    assert health['resource_metrics']['memory_usage_mb'] < 100.0, "Memory usage SLO exceeded"
    print(f"✅ Performance & Impact Monitor verified: Status={health['system_status']}, Avg Latency={health['avg_latency_ms']} ms")

    # 4. Test Component C: Dynamic Policy & Rule Improvement Engine
    print("\n4️⃣ Testing Rule & Policy Improvement Engine (Threshold Tuning & FP Suppression)...")
    improver = PolicyImprovementEngine()
    rule_key = improver.suppress_false_positive_rule(container_id, "bash")
    assert rule_key in improver.dynamic_thresholds['false_positive_suppression_list']
    
    # Simulate FP feedback to test threshold adjustment
    tuned_thresholds = improver.tune_thresholds_from_feedback({'false_positives': 2, 'precision': 0.85})
    assert tuned_thresholds['autoencoder_mse_multiplier'] > 1.0, "Threshold tuning failed"
    print("✅ Policy Improvement Engine verified successfully.")

    # 5. Test Component D: Automated Model Retraining & A/B Canary Deployment Pipeline
    print("\n5️⃣ Testing Automated Model Retraining & A/B Canary Deployment Pipeline...")
    retrained = ModelRetrainingPipeline.trigger_retraining(collector, min_records=1)
    assert retrained, "Model retraining and deployment failed"
    print("✅ Model Retraining & A/B Deployment Pipeline verified successfully.")

    # 6. Test Component E: Master Feedback Engine Orchestration
    print("\n6️⃣ Testing Master Phase 6 Feedback Engine Orchestrator...")
    master_engine = Phase6FeedbackEngine()
    result = master_engine.process_feedback_loop(
        policy_meta['policy_id'],
        container_id,
        inference_result['score'],
        inference_result['severity'],
        mock_anomalous_window,
        feedback_type='TRUE_POSITIVE'
    )
    assert result['retrained'], "Master feedback loop pipeline failed"

    elapsed_ms = (time.time() - start_time) * 1000
    print(f"\n🎉 Phase 6 Continuous Feedback & Learning Loop fully verified in {round(elapsed_ms, 2)} ms!")

if __name__ == "__main__":
    run_phase6_tests()
