# Prometheus Metrics Exporter (PME)

A flexible metrics collection service that monitors multiple systems and exposes metrics in Prometheus format. The service runs as a systemd service and is designed for `/etc/prometheus/exporter`.

## Features

- Multiple service monitoring with automatic user context switching
- File watching for log-based metrics
- HTTP endpoint scraping
- Command execution and parsing
- Dynamic configuration with templates
- Built-in health monitoring

## Quick Start

Intended path: `/etc/prometheus/exporter`

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

### Configuration

Create your configuration file:

```yaml
# /etc/prometheus/exporters/prometheus_metrics_exporter.yml

exporter:
  metrics_port: 9101  # Port for Prometheus metrics
  health_port: 9102   # Port for health API
  poll_interval_sec: 5

services:
  example_service:
    name: "Example Service"
    metric_prefix: "example_"
    run_as:
      user: service_user
      group: service_group
    
    metric_groups:
      status:
        command: "systemctl status example.service"
        metrics:
          running:
            name: "is_running"
            type: "gauge"
            filter: "Active: active \\(running\\)"  # Returns 1 if running, 0 if not
```

### Accessing Metrics

Once running:
- Metrics: `http://localhost:9101/metrics`
- Health: `http://localhost:9102/health`

### Documentation

- [Installation Guide](INSTALL.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [Architecture Overview](docs/ARCHITECTURE.md)

## License

AGPLv3