# Configuration Guide

The Prometheus Metrics Exporter uses YAML configuration for defining metrics collection. Configuration is read from `/etc/prometheus/exporter/prometheus_metrics_exporter.yml`.

## Configuration Sections

### Exporter Configuration
```yaml
exporter:
    name: "Prometheus Metrics Exporter"        # Service name
    description: "General-purpose metrics collection"
    version: "3.0.0"                          # Service version
    metrics_port: 9101                        # Prometheus endpoint port
    health_port: 9102                         # Health API port
    poll_interval_sec: 5                      # Base collection interval
    parallel_collection: true                 # Enable parallel collection
    max_workers: 4                           # Max parallel workers
    failure_threshold: 20                    # Health status threshold
```

### Logging Configuration
```yaml
logging:
    level: "DEBUG"                           # Log level (DEBUG/INFO/WARNING/ERROR)
    max_bytes: 10485760                      # Log file max size (10MB)
    backup_count: 3                          # Number of log backups to keep
```

### Service Templates
Templates define reusable configurations that can be referenced by services.
```yaml
service_templates:
    api_metrics:                             # Template name
        collection_frequency: 30              # Default collection interval
        content_type: "json"                 # Expected response type
        retry_attempts: 3                    # Retry count on failure
    
    file_monitor:
        collection_frequency: 300
        content_type: "json"
        watch_type: "config"
```

### Services Configuration

Services define what metrics to collect. The configuration includes a special `exporter` service that provides self-monitoring metrics. A service represents a collection of related metrics, typically for a specific system or application.

#### Self-Monitoring Service Configuration

The `exporter` service is a special configuration that provides internal health and performance metrics. While it can be disabled by setting `expose_metrics: false`, keeping it enabled is recommended for monitoring the exporter's own health.

```yaml
services:
    exporter:                                # Required self-monitoring service
        name: "Metrics Exporter"
        description: "Self-monitoring metrics"
        metric_prefix: "exporter_"
        ordinal: 1                           # Processing order
        expose_metrics: true                 # Enable/disable metrics output
        
        metric_groups:
            status:
                prefix: "status_"
                ordinal: 1
                metrics:
                    uptime:
                        name: "uptime_seconds"
                        type: "gauge"
                        description: "Service uptime in seconds"
                        category: "health"
```

#### Monitored Services Configuration

A service represents a collection of related metrics, typically for a specific system or application.

```yaml
services:
  example_service:                 # Service identifier
    name: "Example Service"       # Human-readable name
    metric_prefix: "example_"     # Prefix for all service metrics
    collection_frequency_sec: 30  # Optional: service-wide frequency
    run_as:                      # Optional: user context
      user: service_user
      group: service_group
      env:                       # Optional: environment
        VAR_NAME: "value"
    
    metric_groups:              # Groups sharing data source
      ...
    standalone_metrics:         # Independent metrics
      ...
```

## Metric Group Configuration

Metric groups share a single data source, improving collection efficiency.

```yaml
metric_groups:
  status:                          # Group identifier
    command: "systemctl status service"   # Data source
    collection_frequency_sec: 60   # Optional: group frequency
    metrics:
      is_running:                 # Metric identifier
        name: "is_running"        # Metric name
        type: "gauge"            # Metric type
        description: "Service running status"
        filter: "Active: active"  # Value extraction
        value_on_error: 0        # Optional: error fallback
```

## Standalone Metric Configuration

Independent metrics with their own data sources.

```yaml
standalone_metrics:
  disk_usage:                     # Metric identifier
    name: "disk_usage_bytes"     # Metric name
    type: "gauge"                # Metric type
    description: "Disk usage"    # Description
    command: "du -sb /path"      # Data source
    filter: "^(\\d+)"           # Value extraction
    collection_frequency_sec: 300  # Optional: frequency
```

## Data Sources

### Command Source
```yaml
command: "systemctl status service"  # Shell command
```

### File Source
```yaml
source_type: "file"
source: "/path/to/file"          # File path
content_type: "text"            # text/json/prometheus
```

### HTTP Source
```yaml
source_type: "http"
source: "http://localhost:8080/metrics"
method: "GET"                    # HTTP method
content_type: "text"            # text/json/prometheus
```

## Collection Frequency Hierarchy

1. Global (`poll_interval_sec`): Base interval
2. Service (`collection_frequency_sec`): Service override
3. Group/Standalone: Individual overrides

Each level must be ≥ its parent's frequency.

## Dynamic Configuration

The service monitors its configuration file and automatically applies changes:

- Changes apply at next collection interval
- No service restart required
- Partial configurations accepted
- Invalid sections use code defaults

### Modifiable Elements
- Services
- Metric groups
- Standalone metrics
- Collection frequencies
- User contexts

### Best Practices

1. Before Changes:
   - Backup working configuration
   - Test in non-production first
   - Validate YAML syntax

2. During Changes:
   - Make incremental updates
   - Monitor health endpoint
   - Watch service logs
   - Verify metrics output

3. Monitoring Changes:
   ```bash
   # Watch metrics
   curl http://localhost:9101/metrics

   # Check health
   curl http://localhost:9102/health

   # Monitor logs
   journalctl -u prometheus-metrics-exporter -f
   ```

### Recovery

If issues occur:

1. Restore backup:
   ```bash
   cp prometheus_metrics_exporter.yml.backup prometheus_metrics_exporter.yml
   ```

2. Or use minimal configuration:
   ```yaml
   exporter:
     metrics_port: 9101
     health_port: 9102
     poll_interval_sec: 5
   ```

## Complete Example

```yaml
exporter:
  metrics_port: 9101
  health_port: 9102
  poll_interval_sec: 5

services:
  example:
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
            description: "Service running status"
            filter: "Active: active"
    
    standalone_metrics:
      disk_usage:
        name: "data_size_bytes"
        type: "gauge"
        description: "Data directory size"
        command: "du -sb /var/lib/example"
        filter: "^(\\d+)"
        collection_frequency_sec: 300
```