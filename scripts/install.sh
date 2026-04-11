#!/bin/bash
set -e

echo "=== Installing Falco ==="
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco

echo "=== Installing Falcosidekick ==="
wget https://github.com/falcosecurity/falcosidekick/releases/download/2.31.0/falcosidekick_2.31.0_linux_amd64.tar.gz
tar -xzf falcosidekick_2.31.0_linux_amd64.tar.gz
sudo mv falcosidekick /usr/local/bin/
rm falcosidekick_2.31.0_linux_amd64.tar.gz

echo "=== Installing Prometheus ==="
sudo apt-get install -y prometheus

echo "=== Installing Grafana ==="
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update && sudo apt-get install -y grafana

echo "=== Copying configs ==="
sudo cp configs/falco.yaml /etc/falco/falco.yaml
sudo cp configs/falco_rules.local.yaml /etc/falco/falco_rules.local.yaml
sudo cp configs/falcosidekick.yaml /etc/falcosidekick/config.yaml
sudo cp configs/prometheus.yml /etc/prometheus/prometheus.yml
sudo cp configs/grafana.ini /etc/grafana/grafana.ini

echo "=== Creating Falcosidekick systemd service ==="
sudo tee /etc/systemd/system/falcosidekick.service << 'SERVICE'
[Unit]
Description=Falcosidekick
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=/usr/local/bin/falcosidekick -c /etc/falcosidekick/config.yaml

[Install]
WantedBy=multi-user.target
SERVICE

echo "=== Starting all services ==="
sudo systemctl daemon-reload
sudo systemctl enable falco-modern-bpf falcosidekick prometheus grafana-server
sudo systemctl restart falco-modern-bpf falcosidekick prometheus grafana-server

echo ""
echo "=== Setup Complete! ==="
echo "Grafana     : http://localhost:3001 (admin/admin)"
echo "Prometheus  : http://localhost:9090"
echo "Falcosidekick: http://localhost:2801"
