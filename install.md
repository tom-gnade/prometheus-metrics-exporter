# Installation Guide

This guide covers setting up the Prometheus Metrics Exporter (PME) service.

## Prerequisites

- Python 3.8 or higher
- System user with sudo privileges
- systemd-based Linux system

### Update package list
apt update

### Install Python 3 if not present
apt install python3

### Install pip if not present 
apt install python3-pip

### Install venv module
apt install python3-venv

### Verify installations
python3 --version
pip3 --version

## Installation Steps

1. Create service directory:
```bash
sudo mkdir -p /etc/prometheus/exporter
cd /etc/prometheus/exporter
```

2. Set up Python virtual environment:
```bash
sudo python3 -m venv --system-site-packages venv
sudo venv/bin/python -m pip install --upgrade pip
sudo apt install -y libsystemd-dev # Installs systemd development libraries required for cysystemd
```

3. Install requirements:
```bash
sudo venv/bin/pip install -r venv/requirements.txt
```

4. Copy service files:
```bash
sudo cp prometheus_metrics_exporter.py /etc/prometheus/exporter/
sudo cp prometheus_metrics_exporter.yml /etc/prometheus/exporter/
sudo cp prometheus-metrics-exporter.service /etc/systemd/system/
```

5. Configure service:
```bash
# Edit configuration as needed
sudo vim /etc/prometheus/exporter/prometheus_metrics_exporter.yml
```

6. Set permissions:
```bash
sudo chown -R prometheus:prometheus /etc/prometheus/exporter
sudo chmod 755 /etc/prometheus/exporter
sudo chmod 644 /etc/prometheus/exporter/prometheus_metrics_exporter.yml
```

7. Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable prometheus-metrics-exporter
sudo systemctl start prometheus-metrics-exporter
```

## Verify Installation

1. Check service status:
```bash
sudo systemctl status prometheus-metrics-exporter
```

2. Verify metrics endpoint:
```bash
curl http://localhost:9101/metrics
```

3. Check health endpoint:
```bash
curl http://localhost:9102/health
```

## Troubleshooting

### Common Issues

1. Service won't start:
   - Check logs: `sudo journalctl -u prometheus-metrics-exporter -f`
   - Verify Python path in service file
   - Check file permissions

2. Can't access metrics:
   - Verify ports are not in use
   - Check firewall settings
   - Ensure service is running

3. Permission errors:
   - Verify prometheus user exists
   - Check directory permissions
   - Verify config file permissions

## Updating

To update the service:

1. Stop the service:
```bash
sudo systemctl stop prometheus-metrics-exporter
```

2. Update files:
```bash
sudo venv/bin/pip install --upgrade -r requirements.txt
# Copy new files as needed
```

3. Restart service:
```bash
sudo systemctl start prometheus-metrics-exporter
```

## Uninstalling

If you need to remove the service:

```bash
sudo systemctl stop prometheus-metrics-exporter
sudo systemctl disable prometheus-metrics-exporter
sudo rm /etc/systemd/system/prometheus-metrics-exporter.service
sudo rm -rf /etc/prometheus/exporter
sudo systemctl daemon-reload
```