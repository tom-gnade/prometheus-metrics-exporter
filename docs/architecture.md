# Prometheus Metrics Exporter - Architecture

## Overview

The Prometheus Metrics Exporter (PME) is a flexible metrics collection service designed for:
- Multiple service monitoring with user context switching
- File watching with content type handling
- HTTP endpoint scraping
- Dynamic configuration with templates
- Error handling and health checks
- Automatic user permission management

Usage:
    1. Configure services and metrics in the YAML config file
    2. Run directly or as a systemd service
    3. Access metrics at http://localhost:<metrics_port>/metrics
    4. Access health at http://localhost:<health_port>/health

## Core Design Principles

### 1. Source Operation Efficiency
- Each data source read exactly once per collection cycle
- Source operations isolated in metric groups or standalone metrics
- Source-level caching implementation
- Multiple metrics derived from single source read
- Avoid redundant source operations

### 2. Security and Context Management
- User contexts maintained at service level
- Secure permission handling
- User-context-aware command execution
- Permission-verified file operations

### 3. Collection Hierarchy

#### Services
- High-level grouping of related metrics
- Independent data sources/systems
- Manages user permissions and environment
- Contains metric groups and standalone metrics
- Parallel collection capable

#### Metric Groups
- Represents exactly ONE data source
- Efficient source data collection
- Single read per collection cycle
- Parallel collection within service
- Shared caching for group metrics

#### Standalone Metrics
- Independent data sources
- Single value collection
- Fully parallel collection
- Used for simple status checks
- Static value support

## Implementation Architecture

### Data Sources

1. Command Sources
   - Executable system commands
   - RegEx pattern extraction
   - User context execution

2. HTTP Sources
   - REST endpoint monitoring
   - Multiple content type support
   - Response pattern matching

3. File Sources
   - File content monitoring
   - Change-based updates
   - Content caching
   - Permission verification

4. Static Sources
   - Configuration-defined values
   - No external dependencies
   - Constant metrics

### Content Type Support
- Free Text (pattern matching)
- JSON (structured data)
- XML (structured data)
- Prometheus Metrics (direct import)

### Collection Management

#### Frequency Hierarchy
1. Global Frequency (Base Collection Rate)
   - Defined in exporter config
   - Minimum collection interval
   - Non-overridable baseline

2. Service Frequency
   - Optional service-wide setting
   - Must exceed global frequency
   - Applies to all service metrics
   - Collected in multiples of the global frequency

3. Group/Metric Frequency
   - Optional override settings
   - Must exceed service frequency
   - Collected in multiples of the global frequency

#### Collection Timing Rules
```python
next_collection = ceiling(override_frequency / global_frequency) * global_frequency
```

Example:
- Global: 5s
- Service: 30s
- Group: 65s
→ Collections at: 65s, 130s, etc.

### Caching Strategy

1. Command Results
   - Source-level caching
   - 5-second default cache
   - Last value retention
   - Age-based invalidation

2. File Content
   - Modification-based updates
   - Content caching
   - Change monitoring
   - Efficient re-reads

3. HTTP Responses
   - Optional caching
   - Header-based controls
   - Configurable retention

### Security Implementation

1. User Context Management
   - Service-level isolation
   - Permission verification
   - Resource cleanup
   - Secure context switching

2. Access Control
   - File permission checks
   - Command validation
   - Data exposure prevention
   - Resource limitations

### Error Handling

1. Source Failures
   - Error value provision
   - Last value retention
   - Detailed error logging
   - Health metric updates

2. Validation Failures
   - Pattern matching errors
   - Default value handling
   - Metric isolation
   - Error context logging

3. Collection Statistics
   - Success/failure tracking
   - Duration monitoring
   - Health reporting

## Configuration Structure

### Service Configuration
```yaml
services:
  example_service:
    name: str                  # Service identifier
    metric_prefix: str         # Metric prefix
    run_as:                    # User context
      user: str
      group: str
    metric_groups: dict        # Group configs
    standalone_metrics: dict   # Independent metrics
```

### Metric Group Configuration
```yaml
metric_groups:
  example_group:
    source_type: enum          # COMMAND|FILE|HTTP
    source: str                # Source identifier
    metrics: dict              # Metric configs
    collection_frequency: int   # Optional frequency
```

### Metric Configuration
```yaml
metrics:
  example_metric:
    name: str                  # Metric name
    type: enum                # Metric type
    description: str          # Description
    filter: str               # Extract pattern
    value_on_error: float     # Error fallback
```

## Performance Guidelines

1. Resource Management
   - Operation limits
   - Timeout controls
   - Resource cleanup
   - Connection pooling

2. Optimization
   - Operation batching
   - Connection reuse
   - Memory efficiency
   - Cache utilization

## Implementation Priorities
- System impact minimization
- Collection reliability
- Security enforcement
- Configuration flexibility
- Code maintainability