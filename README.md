# Falco eBPF Security Monitoring Stack

Real-time runtime security monitoring using Falco (modern eBPF), Falcosidekick, Prometheus, and Grafana.

## Architecture
## Components
| Component | Version | Port |
|-----------|---------|------|
| Falco | latest | - |
| Falcosidekick | 2.31.0 | 2801 |
| Prometheus | latest | 9090 |
| Grafana | latest | 3001 |

## Quick Install
```bash
git clone <your-repo-url>
cd ebpf
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

## Access
- **Grafana**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Falcosidekick**: http://localhost:2801/ping

## Grafana Dashboard
Import dashboard ID **11914** for the Falco alerts dashboard.

## Verify Installation
```bash
# Check all services
systemctl status falco-modern-bpf
systemctl status falcosidekick
systemctl status prometheus
systemctl status grafana-server

# Trigger a test alert
sudo cat /etc/shadow

# Check alerts are flowing
curl http://localhost:2801/metrics | grep falco
```
