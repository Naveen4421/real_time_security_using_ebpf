import time
import json
import collections
import subprocess
from datetime import datetime

# In-memory sliding window store for container events: {container_id: deque([events])}
# Window size represents 10 seconds or max 100 events
WINDOW_MAX_LEN = 100
sliding_windows = collections.defaultdict(lambda: collections.deque(maxlen=WINDOW_MAX_LEN))

# Local file simulation of cloud stream target
CLOUD_STREAM_FILE = "cloud_stream.json"

def parse_bpf_event(raw_bpf_data):
    """
    Step 1.1 / 1.2: Parse raw BPF event data.
    Handles raw JSON string or dictionary representing syscall telemetry.
    """
    if isinstance(raw_bpf_data, str):
        try:
            event = json.loads(raw_bpf_data)
        except json.JSONDecodeError:
            event = {
                "error": "Failed to decode raw BPF event JSON",
                "raw": raw_bpf_data,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
    elif isinstance(raw_bpf_data, dict):
        event = raw_bpf_data.copy()
    else:
        event = {
            "error": "Unknown raw BPF data format",
            "raw": str(raw_bpf_data),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    
    # Ensure standard keys exist
    if "timestamp" not in event:
        event["timestamp"] = datetime.utcnow().isoformat() + "Z"
    
    return event

def enrich_with_k8s_metadata(parsed_event):
    """
    Step 1.2: Enrich event with K8s metadata.
    Attempts to lookup actual pod information using kubectl command, falling back to mock defaults.
    """
    container_id = parsed_event.get("container_id")
    enriched = parsed_event.copy()
    
    # Defaults
    enriched["node"] = enriched.get("node", "k8s-node-01")
    enriched["namespace"] = enriched.get("namespace", "staging")
    enriched["pod"] = enriched.get("pod", "security-demo-backend")
    
    if not container_id:
        return enriched

    try:
        # Querying live Kubernetes cluster via kubectl JSON output
        cmd = ["kubectl", "get", "pods", "-A", "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            pods_data = json.loads(result.stdout)
            # Search for container_id in pod statuses
            for pod in pods_data.get("items", []):
                status = pod.get("status", {})
                container_statuses = status.get("containerStatuses", [])
                for cs in container_statuses:
                    c_id = cs.get("containerID", "")
                    # containerID is usually docker://abc123def...
                    if container_id in c_id or c_id in container_id:
                        enriched["pod"] = pod["metadata"]["name"]
                        enriched["namespace"] = pod["metadata"]["namespace"]
                        enriched["node"] = pod["spec"].get("nodeName", enriched["node"])
                        break
    except Exception as e:
        # Fallback to defaults on any command error
        pass
        
    return enriched

def add_to_sliding_window(container_id, enriched_event):
    """
    Step 1.2: Add enriched event to sliding window.
    """
    if not container_id:
        container_id = "global"
    sliding_windows[container_id].append(enriched_event)

def compute_window_stats(container_id):
    """
    Step 1.2: Compute statistics on sliding window.
    """
    if not container_id:
        container_id = "global"
    
    window = list(sliding_windows[container_id])
    if not window:
        return {}
    
    # 1. Compute timeline stats
    timestamps = []
    for e in window:
        t_str = e.get("timestamp", "")
        # Remove Z and try to parse
        if t_str.endswith("Z"):
            t_str = t_str[:-1]
        try:
            timestamps.append(datetime.fromisoformat(t_str).timestamp())
        except ValueError:
            pass
            
    # Calculate duration and frequency
    duration = 1.0
    if len(timestamps) > 1:
        duration = max(timestamps) - min(timestamps)
        if duration <= 0:
            duration = 1.0
            
    syscall_frequency = len(window) / duration
    unique_syscalls = len(set(e.get("syscall") for e in window if e.get("syscall")))
    
    # 2. File stats
    file_ops = [e.get("file") for e in window if e.get("file")]
    file_access_rate = len(file_ops) / duration
    unique_files = len(set(file_ops))
    
    sensitive_paths = ["/etc/shadow", "/etc/passwd", "/bin/hack", "/bin/sh", "/bin/bash"]
    sensitive_file_access = sum(1 for f in file_ops if any(s in f for s in sensitive_paths))
    
    # 3. Network stats
    net_events = [e for e in window if e.get("syscall") in ["connect", "accept", "socket"]]
    network_connections = len(net_events)
    unique_ports = len(set(e.get("port") for e in net_events if e.get("port")))
    outbound_traffic = sum(e.get("bytes_sent", 0) for e in window)
    
    # 4. Process stats
    processes = [e.get("process", {}).get("name") for e in window if e.get("process", {}).get("name")]
    process_executions = len(processes)
    unique_processes = len(set(processes))
    process_hierarchy_depth = max([e.get("process", {}).get("depth", 1) for e in window if isinstance(e.get("process"), dict)], default=1)
    
    # 5. Resource averages
    cpu_usages = [e.get("resource_usage", {}).get("cpu", 0) for e in window if isinstance(e.get("resource_usage"), dict)]
    mem_usages = [e.get("resource_usage", {}).get("memory", 0) for e in window if isinstance(e.get("resource_usage"), dict)]
    io_waits = [e.get("resource_usage", {}).get("io", 0) for e in window if isinstance(e.get("resource_usage"), dict)]
    
    avg_cpu = sum(cpu_usages) / len(cpu_usages) if cpu_usages else 0.0
    avg_mem = sum(mem_usages) / len(mem_usages) if mem_usages else 0.0
    avg_io = sum(io_waits) / len(io_waits) if io_waits else 0.0

    stats = {
        "container_id": container_id,
        "window_size": len(window),
        "duration_seconds": round(duration, 3),
        "syscall_frequency": round(syscall_frequency, 3),
        "unique_syscalls": unique_syscalls,
        "file_access_rate": round(file_access_rate, 3),
        "unique_files": unique_files,
        "sensitive_file_access": sensitive_file_access,
        "network_connections": network_connections,
        "unique_ports": unique_ports,
        "outbound_traffic": outbound_traffic,
        "process_executions": process_executions,
        "unique_processes": unique_processes,
        "process_hierarchy_depth": process_hierarchy_depth,
        "cpu_usage": round(avg_cpu, 2),
        "memory_usage": round(avg_mem, 2),
        "io_wait": round(avg_io, 2),
        "last_updated": datetime.utcnow().isoformat() + "Z"
    }
    
    return stats

def stream_to_cloud(stats):
    """
    Step 1.2: Stream computed statistics to the control plane.
    Simulated by appending stats to a local JSON file.
    """
    try:
        try:
            with open(CLOUD_STREAM_FILE, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = []
            
        data.append(stats)
        
        with open(CLOUD_STREAM_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error streaming to cloud: {e}")

def collect_and_stream(raw_bpf_data):
    """
    Phase 1 Orchestrator: Collect events and stream to control plane.
    """
    # 1. Parse raw BPF data
    parsed_event = parse_bpf_event(raw_bpf_data)
    
    # 2. Enrich with K8s metadata
    enriched_event = enrich_with_k8s_metadata(parsed_event)
    
    # 3. Add to sliding window
    container_id = enriched_event.get("container_id", "global")
    add_to_sliding_window(container_id, enriched_event)
    
    # 4. Compute statistics
    stats = compute_window_stats(container_id)
    
    # 5. Stream to cloud
    stream_to_cloud(stats)
    
    return stats
