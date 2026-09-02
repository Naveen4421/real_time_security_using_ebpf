import os
import sys
import json
import time

try:
    from ml_pipeline.model_inference import deploy_model_to_edge, edge_inference
    from ml_pipeline.policy_generation import (
        AnomalyClassifier,
        PolicyLifecycleManager,
        OUTPUT_POLICIES_DIR
    )
    from ml_pipeline.execution_layer import (
        KernelProgramLoader,
        ResponseActionExecutor,
        FalcoConfigUpdater,
        RASPPolicyDeployer,
        Phase5ExecutionEngine,
        LOCAL_FALCO_RULES,
        ACTIVE_RASP_CONFIG
    )
except ImportError:
    from model_inference import deploy_model_to_edge, edge_inference
    from policy_generation import (
        AnomalyClassifier,
        PolicyLifecycleManager,
        OUTPUT_POLICIES_DIR
    )
    from execution_layer import (
        KernelProgramLoader,
        ResponseActionExecutor,
        FalcoConfigUpdater,
        RASPPolicyDeployer,
        Phase5ExecutionEngine,
        LOCAL_FALCO_RULES,
        ACTIVE_RASP_CONFIG
    )

# Mock attack telemetry window
mock_attack_window = [
    {
        "syscall_frequency": 75.0,
        "unique_syscalls": 20,
        "file_access_rate": 45.0,
        "unique_files": 18,
        "sensitive_file_access": 15,
        "network_connections": 30,
        "unique_ports": 10,
        "outbound_traffic": 4000000,
        "process_executions": 30,
        "unique_processes": 16,
        "process_hierarchy_depth": 8,
        "cpu_usage": 95.0,
        "memory_usage": 90.0,
        "io_wait": 40.0
    }
]

def run_phase5_tests():
    print("🚀 Running Phase 5 Real-Time Execution & Response Layer Validation...\n")
    start_time = time.time()

    # 1. Pipeline Prerequisites: Deploy ML models & generate Phase 4 Policy
    print("1️⃣ Deploying Edge Models & Generating Phase 4 Security Policy...")
    deploy_model_to_edge()
    container_id = "demo-compromised-container-99"
    inference_result = edge_inference(container_id, mock_attack_window)
    classification = AnomalyClassifier.classify_anomaly(inference_result, mock_attack_window)
    
    lifecycle_mgr = PolicyLifecycleManager(storage_dir=OUTPUT_POLICIES_DIR)
    policy_meta = lifecycle_mgr.create_and_deploy(classification)
    print(f"✅ Prerequisite Policy Prepared: ID={policy_meta['policy_id']}")

    # 2. Test Component A: Kernel Program Loader
    print("\n2️⃣ Testing Kernel Program Loader (Compile, Verifier, Pin & Attach)...")
    loader = KernelProgramLoader()
    c_file = policy_meta['artifacts']['ebpf']
    o_file = loader.compile_ebpf_c(c_file)
    assert os.path.exists(o_file), "eBPF object file build failed"
    
    is_safe = loader.verify_ebpf_program(o_file)
    assert is_safe, "Kernel BPF verifier failed safety check"
    
    pin_path = loader.load_and_pin(policy_meta['policy_id'], o_file)
    assert pin_path and os.path.exists(pin_path), "BPF pinning failed"
    
    attached = loader.attach_syscall(policy_meta['policy_id'], "sys_enter_execve")
    assert attached, "BPF syscall attachment failed"

    # Test Rollback mechanism
    loader.rollback(policy_meta['policy_id'])
    assert not os.path.exists(pin_path), "Rollback failed to remove BPF pin"
    print("✅ Kernel Program Loader verified successfully (including rollback).")

    # 3. Test Component B: Falco Configuration Hot-Reload
    print("\n3️⃣ Testing Falco Configuration Hot-Reload Engine...")
    falco_updater = FalcoConfigUpdater(target_rules_path=LOCAL_FALCO_RULES)
    reloaded = falco_updater.hot_reload_rule(policy_meta['artifacts']['falco'])
    assert reloaded, "Falco hot-reload failed"
    assert os.path.exists(LOCAL_FALCO_RULES), "Falco rules file missing"
    print("✅ Falco Config Updater verified successfully.")

    # 4. Test Component C: RASP Application Policy Deployer
    print("\n4️⃣ Testing RASP Dynamic Application Policy Deployer...")
    rasp_deployer = RASPPolicyDeployer()
    rasp_deployed = rasp_deployer.deploy_rasp_policy(policy_meta['artifacts']['rasp'])
    assert rasp_deployed, "RASP policy deployment failed"
    assert os.path.exists(ACTIVE_RASP_CONFIG), "Active RASP config file missing"
    print("✅ RASP Policy Deployer verified successfully.")

    # 5. Test Component D: Response Action Executor
    print("\n5️⃣ Testing Active Response Remediation Actions (Talon, Process, Network, File Quarantine)...")
    executor = ResponseActionExecutor()
    assert executor.execute_network_isolation(container_id)
    assert executor.execute_process_kill(pid=9999)
    assert executor.execute_falco_talon_pod_termination(container_id)
    
    # Test file quarantine with mock file
    test_malware = "/tmp/mock_malware.sh"
    with open(test_malware, "w") as f:
        f.write("#!/bin/bash\necho 'malware payload'")
    quarantined_path = executor.execute_file_quarantine(test_malware)
    assert quarantined_path and os.path.exists(quarantined_path), "File quarantine failed"
    print("✅ Response Action Executor verified successfully.")

    # 6. Master Orchestrated Execution Pipeline Test
    print("\n6️⃣ Running Orchestrated Phase 5 Master Engine Pipeline...")
    engine = Phase5ExecutionEngine()
    success = engine.execute_phase5_pipeline(policy_meta)
    assert success, "Phase 5 Master Execution Engine pipeline failed"

    elapsed_ms = (time.time() - start_time) * 1000
    print(f"\n🎉 Phase 5 Real-Time Execution & Response Layer fully verified in {round(elapsed_ms, 2)} ms!")

if __name__ == "__main__":
    run_phase5_tests()
