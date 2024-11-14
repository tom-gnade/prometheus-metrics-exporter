# Prometheus Metrics Exporter Installation Guide
 
This guide covers installing and running the Prometheus Metrics Exporter (PME) for Algorand node monitoring.

## Prerequisites

- Python 3.11 or higher
- System user with sudo privileges
- Linux system (Ubuntu/Debian instructions shown)

## Environment Setup

### 1. Install Python 3.11 and Required System Libraries

```bash
# Add Python repository
sudo add-apt-repository ppa:deadsnakes/ppa

# Update package list
sudo apt update

# Install Python 3.11, development tools, and critical system libraries
sudo apt install -y python3.11 python3.11-venv python3.11-dev libsystemd-dev

# Verify Python installation
python3.11 --version
```

Important: The `libsystemd-dev` package is critical for building the `cysystemd` Python package. Without it, the installation will fail.

### 2. Create Required Users

Save this as `setup-users.sh`:
```bash
#!/bin/bash
# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create prometheus user if it doesn't exist
if ! id "prometheus" &>/dev/null; then
    useradd --no-create-home --shell /sbin/nologin --system --user-group prometheus
fi

# Create algorand user if it doesn't exist
if ! id "algorand" &>/dev/null; then
    useradd --no-create-home --shell /sbin/nologin --system --user-group algorand
fi

# Set up sudo permissions for prometheus user to access docker
if [[ "$1" == "--with-docker" ]]; then
    cat > /etc/sudoers.d/prometheus-docker << EOF
# Allow prometheus user to execute specific docker commands without password
prometheus ALL=(ALL) NOPASSWD: /usr/bin/docker exec algomon-algonode*
prometheus ALL=(ALL) NOPASSWD: /usr/bin/docker stats algomon-algonode*
EOF
    chmod 440 /etc/sudoers.d/prometheus-docker
fi
```

Run with:
```bash
# For standalone Algorand node:
sudo ./setup-users.sh

# For Docker-based node:
sudo ./setup-users.sh --with-docker
```

## Installation

### 1. Create Service Directory and Download Files
```bash
# Create directory
sudo mkdir -p /etc/prometheus/exporter
cd /etc/prometheus/exporter

# Download repository files
sudo curl -L https://api.github.com/repos/tom-gnade/prometheus-metrics-exporter/tarball/main | sudo tar xz --wildcards --strip=2 "*/src"
```

### 2. Set Up Python Environment
```bash
# Create virtual environment
sudo python3.11 -m venv --system-site-packages venv

# Install requirements
sudo ./venv/bin/python -m pip install --upgrade pip
sudo ./venv/bin/pip install prometheus_client pyyaml cysystemd
```

### 3. Set Permissions
```bash
# Set ownership and permissions
sudo chown -R prometheus:prometheus /etc/prometheus/exporter
sudo chmod 755 /etc/prometheus/exporter
sudo chmod 644 /etc/prometheus/exporter/prometheus_metrics_exporter.yml
sudo chmod 755 /etc/prometheus/exporter/prometheus_metrics_exporter.py
```

### 4. Configure for Your Environment

Choose the appropriate configuration based on your setup:

#### For Standalone Algorand Node
```yaml
# /etc/prometheus/exporter/prometheus_metrics_exporter.yml
exporter:
    metrics_port: 9101
    health_port: 9102
    collection:
        poll_interval_sec: 5
    logging:
        console_level: "DEBUG"

services:
    algorand_node:
        description: "Algorand node services"
        run_as: algorand
        metric_groups:
            node_status:
                command: "goal node status -d /var/lib/algorand"
                metrics:
                    sync_time:
                        type: "gauge"
                        description: "Node synchronization time in seconds"
                        filter: "Sync Time: ([0-9.]+)s"
                        labels:
                            genesis_id:
                                filter: "Genesis ID: ([\\w-\\.]+)"
```

#### For Docker-Based Node
```yaml
# /etc/prometheus/exporter/prometheus_metrics_exporter.yml
exporter:
    metrics_port: 9101
    health_port: 9102
    collection:
        poll_interval_sec: 5
    logging:
        console_level: "DEBUG"

services:
    algorand_node:
        description: "Algorand node services in Docker container"
        run_as: prometheus
        metric_groups:
            node_status:
                command: "sudo docker exec algomon-algonode goal node status -d /var/lib/algorand"
                metrics:
                    sync_time:
                        type: "gauge"
                        description: "Node synchronization time in seconds"
                        filter: "Sync Time: ([0-9.]+)s"
                        labels:
                            genesis_id:
                                filter: "Genesis ID: ([\\w-\\.]+)"
```

## Running the Exporter

### Direct Run (Foreground)
```bash
sudo -u prometheus /etc/prometheus/exporter/venv/bin/python /etc/prometheus/exporter/prometheus_metrics_exporter.py
```

### Background Run with Control
```bash
# Start in background
sudo -u prometheus nohup /etc/prometheus/exporter/venv/bin/python /etc/prometheus/exporter/prometheus_metrics_exporter.py > /etc/prometheus/exporter/exporter.log 2>&1 &

# Save the PID for later
echo $! > /etc/prometheus/exporter/exporter.pid

# To stop the exporter
kill $(cat /etc/prometheus/exporter/exporter.pid)
```

## Verification

### Check Metrics Endpoint
```bash
curl http://localhost:9101/metrics
```

### Check Health Endpoint
```bash
curl http://localhost:9102/health
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Check user exists: `id prometheus`
   - Verify file permissions: `ls -l /etc/prometheus/exporter/`
   - Check directory ownership: `ls -ld /etc/prometheus/exporter/`

2. **Docker Access Issues**
   - Verify sudo permissions: `sudo -l -U prometheus`
   - Check Docker container name matches configuration
   - Ensure Docker container is running: `docker ps`

3. **Python/Dependencies Issues**
   - Verify Python version: `./venv/bin/python --version`
   - Check installed packages: `./venv/bin/pip list`
   - Verify venv permissions: `ls -l /etc/prometheus/exporter/venv/bin/`

### Logs
- Check exporter logs: `tail -f /etc/prometheus/exporter/exporter.log`
- Check system logs: `sudo journalctl -f`

## Notes

- SystemD service setup instructions are available but deferred for now
- The exporter requires proper permissions to access either the local Algorand node or Docker container
- For Docker setups, ensure the container name matches your configuration
- Background run creates a PID file for easy management