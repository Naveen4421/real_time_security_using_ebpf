import os
import sys
import json
import time

try:
    from ml_pipeline.production_pipeline import (
        SecurityHardeningManager,
        ErrorRecoveryManager,
        PerformanceOptimizer,
        MultiTenantIsolationManager,
        Phase8ProductionEngine
    )
except ImportError:
    from production_pipeline import (
        SecurityHardeningManager,
        ErrorRecoveryManager,
        PerformanceOptimizer,
        MultiTenantIsolationManager,
        Phase8ProductionEngine
    )

mock_telemetry = [
    {
        "syscall_frequency": 95.0,
        "unique_syscalls": 25,
        "file_access_rate": 60.0,
        "unique_files": 22,
        "sensitive_file_access": 18,
        "network_connections": 40,
        "unique_ports": 15,
        "outbound_traffic": 6500000,
        "process_executions": 42,
        "unique_processes": 20,
        "process_hierarchy_depth": 10,
        "cpu_usage": 99.5,
        "memory_usage": 95.0,
        "io_wait": 52.0
    }
]

def run_phase8_tests():
    print("🚀 Running Phase 8 Production Readiness & Master Pipeline Validation...\n")
    start_time = time.time()

    # 1. Test Component A: Security Hardening Engine
    print("1️⃣ Testing Security Hardening & Input Sanitization...")
    sanitized = SecurityHardeningManager.sanitize_input("c123; rm -rf /")
    assert ";" not in sanitized and "rm" in sanitized, "Sanitization failed"
    
    # Test command injection block in validate_container_id
    try:
        SecurityHardeningManager.validate_container_id("malicious_id; rm -rf /")
        assert False, "Should have thrown ValueError"
    except ValueError:
        print("  🛡️ Security Hardening: Successfully blocked malicious container ID input!")

    valid_id = SecurityHardeningManager.validate_container_id("c8f921a301ef98234")
    assert valid_id == "c8f921a301ef98234"
    
    headers = SecurityHardeningManager.get_security_headers()
    assert 'Content-Security-Policy' in headers and 'X-Frame-Options' in headers
    print(f"✅ Security Hardening verified: Clean Input='{sanitized}', Headers={len(headers)}")

    # 2. Test Component B: Error Recovery & Circuit Breaker Engine
    print("\n2️⃣ Testing Error Recovery, Circuit Breaker & Health Probes...")
    recovery = ErrorRecoveryManager(failure_threshold=2, reset_timeout_sec=1)
    
    def dummy_success():
        return "SUCCESS"
    
    res = recovery.execute_with_circuit_breaker(dummy_success)
    assert res == "SUCCESS", "Circuit breaker execution failed"
    
    health = recovery.get_health_status()
    assert health['status'] == "UP" and health['checks']['ebpf_probes'] == "OK"
    print(f"✅ Error Recovery & Health Probes verified: Health Status={health['status']}")

    # 3. Test Component C: Performance Optimizer & Multi-Tenant Isolation
    print("\n3️⃣ Testing Performance Optimization & Multi-Tenant Isolation...")
    optimizer = PerformanceOptimizer()
    optimizer.cache_put("key1", "val1")
    assert optimizer.cache_get("key1") == "val1"
    
    tenants = MultiTenantIsolationManager()
    reg = tenants.register_tenant_policy("tenant-finance")
    assert reg, "Tenant registration failed"
    print("✅ Performance & Multi-Tenant Isolation verified successfully.")

    # 4. Test Component D: Full 8-Phase Master End-to-End Autonomous Pipeline
    print("\n4️⃣ Testing Complete 8-Phase End-to-End Autonomous Security Simulator...")
    production_engine = Phase8ProductionEngine()
    result = production_engine.run_full_pipeline(
        raw_container_id="prod-container-999",
        telemetry_window=mock_telemetry,
        tenant_id="tenant-default"
    )
    
    assert result['status'] == 'SUCCESS', "Full pipeline execution failed"
    assert result['container_id'] == "prod-container-999"
    assert result['policy_id'], "Policy ID missing"
    assert result['total_latency_ms'] < 10000.0

    elapsed_ms = (time.time() - start_time) * 1000
    print(f"\n🎉 Phase 8 Production Readiness & Full 8-Phase Pipeline verified in {round(elapsed_ms, 2)} ms!")

if __name__ == "__main__":
    run_phase8_tests()
