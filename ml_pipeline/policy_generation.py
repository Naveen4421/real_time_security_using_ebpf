import os
import sys
import json
import time
import yaml
import re
from datetime import datetime

# Import inference capabilities from Phase 3
try:
    from ml_pipeline.model_inference import edge_inference, deploy_model_to_edge
except ImportError:
    from model_inference import edge_inference, deploy_model_to_edge

# Directory for generated dynamic policy artifacts
OUTPUT_POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "configs", "generated_policies")
os.makedirs(OUTPUT_POLICIES_DIR, exist_ok=True)


class AnomalyClassifier:
    """
    Step 4.1: Anomaly Type Mapping & Threat Classifier.
    Maps raw feature vectors and inference anomaly scores into specific threat types and severity levels.
    """
    ANOMALY_TYPES = {
        'SENSITIVE_FILE_ACCESS': 'Unauthorized access or exfiltration from restricted system paths',
        'PROCESS_EXECUTION_ABUSE': 'Suspicious shell spawn or privilege escalation depth',
        'NETWORK_EXFILTRATION': 'Abnormal outbound network traffic volume or port connections',
        'RESOURCE_HIJACKING': 'Sudden spike in CPU/Memory usage indicating cryptomining or DoS'
    }

    @staticmethod
    def classify_anomaly(inference_result, event_window):
        """
        Classifies anomaly based on feature bounds and inference results.
        """
        score = inference_result.get('score', 0.0)
        severity = inference_result.get('severity', 'LOW')
        container_id = inference_result.get('container_id', 'unknown')

        # Analyze aggregate metrics across the window
        features = event_window[-1] if event_window else {}
        sensitive_files = features.get('sensitive_file_access', 0)
        process_depth = features.get('process_hierarchy_depth', 1)
        outbound_bytes = features.get('outbound_traffic', 0)
        cpu_usage = features.get('cpu_usage', 0.0)

        detected_types = []
        if sensitive_files > 0:
            detected_types.append('SENSITIVE_FILE_ACCESS')
        if process_depth > 3 or features.get('process_executions', 0) > 10:
            detected_types.append('PROCESS_EXECUTION_ABUSE')
        if outbound_bytes > 100000 or features.get('unique_ports', 0) > 5:
            detected_types.append('NETWORK_EXFILTRATION')
        if cpu_usage > 75.0 or features.get('syscall_frequency', 0) > 40:
            detected_types.append('RESOURCE_HIJACKING')

        if not detected_types and severity != 'LOW':
            detected_types.append('PROCESS_EXECUTION_ABUSE')

        confidence = round(min(0.99, max(0.50, score / 100.0 if score > 1.0 else score)), 4)

        return {
            'container_id': container_id,
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'anomaly_score': score,
            'severity': severity,
            'confidence': confidence,
            'detected_types': detected_types,
            'details': {
                'sensitive_file_access_count': sensitive_files,
                'process_depth': process_depth,
                'outbound_bytes': outbound_bytes,
                'cpu_usage': cpu_usage
            }
        }


class PolicyGenerator:
    """
    Step 4.2: Dynamic Policy Generation Engine.
    Produces eBPF C programs, Falco YAML rules, Falco Talon remediation rules, and RASP policies.
    """
    
    @staticmethod
    def generate_ebpf_c_code(policy_id, container_id, detected_types):
        """
        Generates dynamic C eBPF kernel program targeting the container.
        """
        c_code = f"""/* Auto-generated eBPF Security Filter Policy: {policy_id} */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TARGET_CONTAINER "{container_id[:12]}"

struct event_t {{
    u32 pid;
    u32 uid;
    char comm[16];
    char container_id[16];
    u32 action_code; // 1=BLOCK, 2=ALERT, 3=TERMINATE
}};

SEC("kprobe/sys_enter_execve")
int BPF_KPROBE(ebpf_filter_{policy_id[:8]}, const char *filename) {{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // Dynamic Filter Rule for Policy {policy_id}
    // Target Container: {container_id}
    // Threat Types: {", ".join(detected_types)}
    
    bpf_printk("eBPF Policy {policy_id[:8]} triggered for container %s (PID: %d)\\n", TARGET_CONTAINER, pid);
    
    // Return non-zero to signify drop/block action for critical threats
    return 1;
}}

char LICENSE[] SEC("license") = "GPL";
"""
        return c_code

    @staticmethod
    def generate_falco_rule(policy_id, container_id, severity, detected_types):
        """
        Generates a custom Falco YAML rule.
        """
        falco_priority = "CRITICAL" if severity == "CRITICAL" else ("WARNING" if severity == "HIGH" else "NOTICE")
        
        condition_parts = [f"container.id startswith '{container_id[:12]}'"]
        if 'SENSITIVE_FILE_ACCESS' in detected_types:
            condition_parts.append("(evt.type = openat and fd.name startswith '/etc')")
        if 'PROCESS_EXECUTION_ABUSE' in detected_types:
            condition_parts.append("(evt.type = execve and proc.name in (bash, sh, nc))")
        
        rule_struct = {
            'custom_rules': [{
                'rule': f"eBPF_ML_Anomaly_{policy_id[:8]}",
                'desc': f"Dynamic ML Anomaly policy for container {container_id}",
                'condition': " and ".join(condition_parts),
                'output': f"Dynamic eBPF ML Anomaly Detected (container=%container.id severity={severity} types={','.join(detected_types)})",
                'priority': falco_priority,
                'tags': ['ebpf_ml', 'auto_generated', severity.lower()]
            }]
        }
        return yaml.dump(rule_struct, sort_keys=False)

    @staticmethod
    def generate_talon_rule(policy_id, container_id, severity):
        """
        Generates Falco Talon remediation rule YAML.
        """
        action = "kubernetes:terminate" if severity in ['CRITICAL', 'HIGH'] else "process:kill"
        talon_struct = {
            'version': 'v1alpha1',
            'actionners': [{
                'name': f"remediate-{policy_id[:8]}",
                'description': f"Auto-generated remediation for {severity} anomaly in container {container_id[:12]}",
                'match': {
                    'rules': [f"eBPF_ML_Anomaly_{policy_id[:8]}"]
                },
                'actions': [{
                    'action': action,
                    'parameters': {
                        'grace_period': 0 if severity == 'CRITICAL' else 5
                    }
                }]
            }]
        }
        return yaml.dump(talon_struct, sort_keys=False)

    @staticmethod
    def generate_rasp_policy(policy_id, container_id, severity, detected_types):
        """
        Generates Application-Level RASP policy JSON.
        """
        rasp_policy = {
            'policy_id': policy_id,
            'container_id': container_id,
            'severity': severity,
            'created_at': datetime.utcnow().isoformat() + "Z",
            'active': True,
            'lockdown_routes': ['/api/admin', '/api/exec'] if severity in ['CRITICAL', 'HIGH'] else [],
            'quarantine_files': ['/bin/hack', '/tmp/malware.sh'],
            'rate_limit_per_min': 10 if severity == 'CRITICAL' else 60
        }
        return json.dumps(rasp_policy, indent=2)


class PolicyValidator:
    """
    Step 4.3: Policy Syntax and Semantic Validation Engine.
    """
    @staticmethod
    def validate_yaml(yaml_content):
        try:
            parsed = yaml.safe_load(yaml_content)
            return parsed is not None
        except Exception as e:
            print(f"❌ YAML Validation Error: {e}")
            return False

    @staticmethod
    def validate_ebpf_c(c_content):
        # Verify required BPF headers, SEC definition, and license
        required_tokens = ['SEC(', 'char LICENSE[]', 'return', '#include']
        for token in required_tokens:
            if token not in c_content:
                print(f"❌ eBPF C Validation Error: Missing token '{token}'")
                return False
        return True

    @staticmethod
    def validate_rasp_json(json_content):
        try:
            parsed = json.loads(json_content)
            return 'policy_id' in parsed and 'severity' in parsed
        except Exception as e:
            print(f"❌ RASP JSON Validation Error: {e}")
            return False


class PolicyLifecycleManager:
    """
    Step 4.4: Policy Lifecycle & Storage Manager.
    Handles staging, deployment, persistence, active cache, and cleanup.
    """
    def __init__(self, storage_dir=OUTPUT_POLICIES_DIR):
        self.storage_dir = storage_dir
        self.active_policies = {}
        self.audit_log = []

    def create_and_deploy(self, classification_result):
        container_id = classification_result['container_id']
        severity = classification_result['severity']
        detected_types = classification_result['detected_types']
        
        policy_id = f"pol-{int(time.time())}-{container_id[:6]}"
        
        # 1. Render policy variants
        ebpf_c = PolicyGenerator.generate_ebpf_c_code(policy_id, container_id, detected_types)
        falco_yaml = PolicyGenerator.generate_falco_rule(policy_id, container_id, severity, detected_types)
        talon_yaml = PolicyGenerator.generate_talon_rule(policy_id, container_id, severity)
        rasp_json = PolicyGenerator.generate_rasp_policy(policy_id, container_id, severity, detected_types)

        # 2. Validate all policy templates
        val_c = PolicyValidator.validate_ebpf_c(ebpf_c)
        val_falco = PolicyValidator.validate_yaml(falco_yaml)
        val_talon = PolicyValidator.validate_yaml(talon_yaml)
        val_rasp = PolicyValidator.validate_rasp_json(rasp_json)

        if not (val_c and val_falco and val_talon and val_rasp):
            raise ValueError(f"Policy validation failed for generated policy {policy_id}")

        # 3. Persist artifacts
        ebpf_file = os.path.join(self.storage_dir, f"{policy_id}.c")
        falco_file = os.path.join(self.storage_dir, f"{policy_id}_falco.yaml")
        talon_file = os.path.join(self.storage_dir, f"{policy_id}_talon.yaml")
        rasp_file = os.path.join(self.storage_dir, f"{policy_id}_rasp.json")

        with open(ebpf_file, "w") as f:
            f.write(ebpf_c)
        with open(falco_file, "w") as f:
            f.write(falco_yaml)
        with open(talon_file, "w") as f:
            f.write(talon_yaml)
        with open(rasp_file, "w") as f:
            f.write(rasp_json)

        # 4. Cache & Audit
        policy_meta = {
            'policy_id': policy_id,
            'container_id': container_id,
            'severity': severity,
            'status': 'ACTIVE',
            'created_at': datetime.utcnow().isoformat() + "Z",
            'ttl_seconds': 3600,
            'artifacts': {
                'ebpf': ebpf_file,
                'falco': falco_file,
                'talon': talon_file,
                'rasp': rasp_file
            }
        }
        self.active_policies[policy_id] = policy_meta
        self.audit_log.append({
            'action': 'POLICY_CREATED',
            'policy_id': policy_id,
            'timestamp': datetime.utcnow().isoformat() + "Z"
        })

        return policy_meta


class PolicyAnalytics:
    """
    Step 4.5: Analytics & Metrics Engine (Precision, Recall, Latency).
    """
    @staticmethod
    def calculate_metrics(tp, fp, fn, tn, latency_ms):
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1_score = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positive_rate': fpr,
            'detection_latency_ms': round(latency_ms, 2),
            'latency_compliant': latency_ms < 50.0
        }
