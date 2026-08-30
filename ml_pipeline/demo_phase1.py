import time
import random
import json
import sys
from datetime import datetime
from data_collection import collect_and_stream

# List of mock processes, system calls, and target files to simulate realistic telemetry
processes = [
    {"name": "nginx", "depth": 1, "cpu": 2, "memory": 15},
    {"name": "node", "depth": 1, "cpu": 8, "memory": 45},
    {"name": "python3", "depth": 2, "cpu": 12, "memory": 35},
    {"name": "bash", "depth": 3, "cpu": 1, "memory": 5},
    {"name": "curl", "depth": 4, "cpu": 3, "memory": 8},
    {"name": "cat", "depth": 3, "cpu": 1, "memory": 2}
]

syscalls = ["openat", "execve", "connect", "accept", "write", "read"]

files = [
    "/app/server.js", "/etc/shadow", "/bin/hack", "/etc/passwd", 
    "/var/log/nginx/access.log", "/tmp/temp_cache.tmp", "/app/frontend/index.html"
]

container_ids = ["container-backend-9f8e", "container-frontend-1a2b"]

print("======================================================================")
print("             eBPF ML Pipeline: Phase 1 Live Telemetry Demo             ")
print("======================================================================")
print("Press Ctrl+C to stop the simulation.\n")

try:
    step = 1
    while True:
        # 1. Randomly generate a realistic event
        proc = random.choice(processes)
        sys_call = random.choice(syscalls)
        target_file = random.choice(files) if sys_call in ["openat", "write", "read"] else None
        
        raw_event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "container_id": random.choice(container_ids),
            "syscall": sys_call,
            "process": {
                "name": proc["name"],
                "pid": random.randint(1000, 30000),
                "depth": proc["depth"]
            },
            "resource_usage": {
                "cpu": proc["cpu"] + random.randint(-2, 3),
                "memory": proc["memory"] + random.randint(-5, 5),
                "io": random.randint(0, 10)
            }
        }
        
        if target_file:
            raw_event["file"] = target_file
            
        # Network event enrichment
        if sys_call in ["connect", "accept"]:
            raw_event["port"] = random.choice([80, 443, 5000, 8080, 27017])
            raw_event["bytes_sent"] = random.randint(100, 50000)

        # 2. Run through Phase 1 collect_and_stream pipeline
        stats = collect_and_stream(raw_event)
        
        # 3. Print dynamic console report
        print(f"\r[{datetime.now().strftime('%H:%M:%S')}] Step {step:03d} | Generated Event: {raw_event['syscall']} by {raw_event['process']['name']}")
        print(f"  Container: {stats['container_id']} | Window Events: {stats['window_size']} | Duration: {stats['duration_seconds']}s")
        print(f"  Syscall Rate: {stats['syscall_frequency']}/sec | Unique Syscalls: {stats['unique_syscalls']}")
        print(f"  File Ops Rate: {stats['file_access_rate']}/sec | Sensitive File Hits: {stats['sensitive_file_access']}")
        print(f"  Max Process Depth: {stats['process_hierarchy_depth']} | Unique Command Names: {stats['unique_processes']}")
        print(f"  Avg CPU: {stats['cpu_usage']}% | Avg Memory: {stats['memory_usage']}% | Avg IO Wait: {stats['io_wait']}%")
        print("-" * 70)
        
        step += 1
        time.sleep(1.2)  # Pause between events to simulate real-time streaming

except KeyboardInterrupt:
    print("\n\nSimulation stopped by user.")
    print("Check 'ml_pipeline/cloud_stream.json' to see the full set of streamed telemetry packages.")
    sys.exit(0)
