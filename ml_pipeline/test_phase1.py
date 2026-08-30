import json
import time
from data_collection import collect_and_stream

# Mock events matching Phase 1 spec
mock_events = [
    {
        'timestamp': '2026-08-31T10:15:25Z',
        'container_id': 'abc123def456',
        'syscall': 'openat',
        'process': {'name': 'node', 'pid': 5000, 'depth': 1},
        'file': '/app/server.js',
        'resource_usage': {'cpu': 5, 'memory': 30, 'io': 1}
    },
    {
        'timestamp': '2026-08-31T10:15:27Z',
        'container_id': 'abc123def456',
        'syscall': 'execve',
        'process': {'name': 'bash', 'pid': 12345, 'depth': 2},
        'file': '/bin/bash',
        'resource_usage': {'cpu': 15, 'memory': 35, 'io': 2}
    },
    {
        'timestamp': '2026-08-31T10:15:30Z',
        'container_id': 'abc123def456',
        'syscall': 'execve',
        'process': {'name': 'bash', 'pid': 12345, 'depth': 2},
        'file': '/etc/shadow',
        'resource_usage': {'cpu': 25, 'memory': 40, 'io': 5}
    }
]

print("🚀 Testing Phase 1: Data Collection & Observation\n")

for i, raw_event in enumerate(mock_events):
    print(f"--- Firing Event {i+1}: syscall={raw_event['syscall']} file={raw_event.get('file', 'N/A')} ---")
    stats = collect_and_stream(raw_event)
    print("Computed Statistics:")
    print(json.dumps(stats, indent=2))
    print()

print("Checking cloud_stream.json outputs:")
try:
    with open("cloud_stream.json", "r") as f:
        data = json.load(f)
    print(f"Total stats packages streamed to cloud: {len(data)}")
    print(f"Latest streamed stats package:\n{json.dumps(data[-1], indent=2)}")
except Exception as e:
    print(f"Error reading cloud_stream.json: {e}")
