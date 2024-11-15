#!/etc/prometheus/exporter/venv/bin/python3 -u

"""
Prometheus Metrics Exporter

Description:
---------------------

A flexible metrics collection and exposition service supporting:
- Multiple service monitoring with user context switching
- File watching with content type handling
- HTTP endpoint scraping
- Dynamic configuration reloading 
- Error handling and health checks
- Automatic user permission management

Usage:
---------------------
1. Create a YAML configuration file in the same directory as the script
2. Ensure proper user permissions are configured
3. Run the script directly or via systemd service
4. Monitor metrics at http://localhost:9101/metrics
5. Check service health at http://localhost:9102/health

Configuration:
---------------------

exporter:
    metrics_port: 9101  # Prometheus metrics port (requires restart to change)
    health_port: 9102   # Health check port (requires restart to change)
    user: prometheus    # User to run commands as
    collection:
        poll_interval_sec: 5    # Global collection interval
        max_workers: 4          # Parallel collection workers
        failure_threshold: 20   # Collection failures before unhealthy
        collection_timeout_sec: 30  # Timeout for collection operations
    logging:
        level: "DEBUG"         # Main logging level
        file_level: "DEBUG"    # File logging level
        console_level: "INFO"  # Console output level
        journal_level: "WARNING"  # Systemd journal level
        max_bytes: 10485760    # Log file size limit (10MB)
        backup_count: 3        # Log file rotation count
        format: "%(asctime)s [%(process)d] [%(threadName)s] [%(name)s.%(funcName)s] [%(levelname)s] %(message)s"
        date_format: "%Y-%m-%d %H:%M:%S"

# Note: All exporter section changes require service restart

services:
    service_name:              # Each service to monitor
        description: "Service description"
        run_as: username       # Optional username to execute commands
        metric_groups:
            group_name:        # Logical grouping of metrics that share a command
                command: "shell command that produces output"  # Required for dynamic groups
                type: "dynamic|static"  # Optional, defaults to dynamic
                metrics:
                    metric_name:
                        type: "gauge|counter"  # Required for dynamic metrics
                        description: "Metric description"  # Required description
                        filter: "regex or jq-style filter"  # Required for dynamic metrics
                        content_type: "text|json"  # How to parse output, default text
                        value: 1.0  # Required for static metrics only

    transform: "transform expression"  # Optional transform for parsed value
        - Basic math: value * 1000, value / 2
        - Conditionals: value == 200 and 1 or 0
        - Time helpers: unix_nano_to_sec(value), unix_micro_to_sec(value)
        - Time formats: to_timestamp(value, SYSTEMD), now - timestamp
                        

Health Check API:
---------------------
GET /health
Returns service health status and operational metrics

Query Parameters:
    include_metrics=true: Include full metrics inventory

Response Codes:
    200: Service healthy
    503: Service unhealthy
    404: Invalid endpoint

Features:
---------------------
- Dynamic configuration reloading with optimistic validation
- Partial configuration updates (services only)
- Graceful handling of configuration errors
- Parallel metric collection
- User context switching for command execution 
- Prometheus metrics exposition
- Health check endpoint with detailed status
- Comprehensive logging with rotation
- Systemd integration
- Automatic sudo permission management

Dependencies:
---------------------
- Python 3.11+
- prometheus_client
- pyyaml
- cysystemd (for systemd integration)

Notes:
---------------------
- All timestamps are in UTC
- Configuration file must be in same directory as script
- Script must run as root for user switching functionality
- Proper sudo rules are required for user context switching
- Exporter section changes require service restart
- Services section supports live reloading with validation
- Invalid configuration components are skipped with warnings
"""

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Imports
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

# Standard library imports
import asyncio
import json
import logging
import inspect
import os
import pwd
import grp
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import (
    Any, Awaitable, Callable, Dict, List, Optional, 
    Tuple, TYPE_CHECKING, Union
)
from wsgiref.simple_server import make_server

# Third party imports
from prometheus_client import (
   Counter, Gauge, make_wsgi_app, start_http_server
)
from cysystemd.daemon import notify, Notification
from cysystemd import journal
import yaml

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Global Configuration
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

# Enable/disable verbose debug logging
VERBOSE_DEBUG = True

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Core Exceptions
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricError(Exception):
    """Base class for metric-related errors."""
    pass

class MetricConfigurationError(MetricError):
    """Error in metric configuration."""
    pass

class MetricCollectionError(MetricError):
    """Error during metric collection."""
    pass

class MetricValidationError(MetricError):
    """Error during metric validation."""
    pass

class UserConfigurationError(Exception):
    """Error in user configuration or management."""
    pass

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Core Enums and Data Classes
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

@dataclass(frozen=True)
class ProgramSource:
    """Program source and derived file configurations."""
    script_path: Path = field(default_factory=lambda: Path(sys.argv[0]).resolve())
    
    @property
    def script_dir(self) -> Path:
        """Directory containing the script."""
        return self.script_path.parent
    
    @property
    def base_name(self) -> str:
        """Base name without extension."""
        return self.script_path.stem
        
    @property
    def logger_name(self) -> str:
        """Logger name derived from script name."""
        return self.base_name
    
    @property
    def config_path(self) -> Path:
        """Full path to config file."""
        path = self.script_dir / f"{self.base_name}.yml"
        if path.is_file() and os.access(path, os.R_OK):
            return path

        raise FileNotFoundError(
            f"Config file {path} not found"
        )

    @property
    def log_path(self) -> Path:
        """Full path to log file."""
        path = self.script_dir / f"{self.base_name}.log"
        
        if os.access(path, os.W_OK):
            return path

        raise PermissionError(
            f"No writable log file at {path}"
        )

    @property
    def sudoers_file(self) -> str:
        """Name for sudoers configuration file."""
        return self.base_name

    @property
    def sudoers_path(self) -> Path:
        """Full path to sudoers configuration file."""
        return Path("/etc/sudoers.d") / self.sudoers_file

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ProgramConfig:
    """Program configuration with simplified defaults and validation."""
    
    # Default values as class attributes - explicit and easy to maintain
    DEFAULT_METRICS_PORT = 9101
    DEFAULT_HEALTH_PORT = 9102
    DEFAULT_EXPORTER_USER = 'prometheus'
    DEFAULT_POLL_INTERVAL = 5
    DEFAULT_MAX_WORKERS = 4
    DEFAULT_FAILURE_THRESHOLD = 20
    DEFAULT_COLLECTION_TIMEOUT = 30
    
    # Logging defaults
    DEFAULT_LOG_LEVEL = 'DEBUG'
    DEFAULT_LOG_FILE_LEVEL = 'DEBUG'
    DEFAULT_LOG_CONSOLE_LEVEL = 'INFO'
    DEFAULT_LOG_JOURNAL_LEVEL = 'WARNING'
    DEFAULT_LOG_MAX_BYTES = 10485760  # 10MB
    DEFAULT_LOG_BACKUP_COUNT = 3
    DEFAULT_LOG_FORMAT = '%(asctime)s [%(process)d] [%(threadName)s] [%(name)s.%(funcName)s] [%(levelname)s] %(message)s'
    DEFAULT_LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, source: ProgramSource):
        """Initialize configuration manager."""
        self._source = source
        self._config = {'exporter': self._get_exporter_defaults()}
        self._initial_exporter = {}
        self._last_load_time = self._source.config_path.stat().st_mtime
        self._lock = threading.Lock()
        self._running_under_systemd = bool(os.getenv('INVOCATION_ID'))
        self._start_time = self.now_utc()
        self.logger = None
        
        # Track validation status
        self._validation_stats = {
            'services': {'valid': 0, 'invalid': 0},
            'groups': {'valid': 0, 'invalid': 0},
            'metrics': {'valid': 0, 'invalid': 0}
        }

    def _log_message(self, level: str, message: str) -> None:
        """Safe logging wrapper."""
        if self.logger:
            getattr(self.logger, level)(message)

    def initialize(self) -> None:
        """Complete initialization after logger is attached."""
        try:
            self.load(initial_load=True)
        except Exception as e:
            self._log_message('error', f"Failed to load initial configuration: {e}")
            raise

    def _get_exporter_defaults(self) -> Dict[str, Any]:
        """Get default exporter configuration."""
        return {
            'metrics_port': self.DEFAULT_METRICS_PORT,
            'health_port': self.DEFAULT_HEALTH_PORT,
            'user': self.DEFAULT_EXPORTER_USER,
            'collection': {
                'poll_interval_sec': self.DEFAULT_POLL_INTERVAL,
                'max_workers': self.DEFAULT_MAX_WORKERS,
                'failure_threshold': self.DEFAULT_FAILURE_THRESHOLD,
                'collection_timeout_sec': self.DEFAULT_COLLECTION_TIMEOUT
            },
            'logging': {
                'level': self.DEFAULT_LOG_LEVEL,
                'file_level': self.DEFAULT_LOG_FILE_LEVEL,
                'console_level': self.DEFAULT_LOG_CONSOLE_LEVEL,
                'journal_level': self.DEFAULT_LOG_JOURNAL_LEVEL,
                'max_bytes': self.DEFAULT_LOG_MAX_BYTES,
                'backup_count': self.DEFAULT_LOG_BACKUP_COUNT,
                'format': self.DEFAULT_LOG_FORMAT,
                'date_format': self.DEFAULT_LOG_DATE_FORMAT
            }
        }

    def _reset_validation_stats(self):
        """Reset validation statistics."""
        for section in self._validation_stats.values():
            section['valid'] = 0
            section['invalid'] = 0

    def load(self, initial_load: bool = False) -> None:
        """Load configuration with simplified validation."""
        with self._lock:
            try:
                self._reset_validation_stats()
                
                # Start with default values
                new_config = {
                    'exporter': self._get_exporter_defaults(),
                    'services': {}
                }

                # Load configuration file
                try:
                    with open(self._source.config_path) as f:
                        file_config = yaml.safe_load(f) or {}
                except Exception as e:
                    raise MetricConfigurationError(f"Failed to load config file: {e}")

                if initial_load:
                    # Validate and merge exporter section
                    if 'exporter' in file_config:
                        self._validate_exporter_section(file_config['exporter'])
                        # Merge while preserving defaults for missing values
                        new_config['exporter'] = self._merge_with_defaults(
                            new_config['exporter'],
                            file_config['exporter']
                        )
                    self._initial_exporter = deepcopy(new_config['exporter'])
                else:
                    # Use initial exporter config after first load
                    new_config['exporter'] = deepcopy(self._initial_exporter)

                # Validate services section
                if 'services' not in file_config:
                    raise MetricConfigurationError("Missing required 'services' section")
                
                # Validate and store services
                new_config['services'] = self._validate_services(file_config['services'])

                # Update configuration
                old_config = self._config
                self._config = new_config
                self._last_load_time = self._source.config_path.stat().st_mtime
                
                # Log validation summary
                self._log_validation_summary(initial_load)

                # If this is a reload (not initial load) and the services changed,
                # notify any registered callbacks
                if not initial_load and old_config.get('services') != new_config['services']:
                    if hasattr(self, 'on_config_reload') and self.on_config_reload:
                        self.logger.info("Services configuration changed, triggering reload callback")
                        self.on_config_reload()

            except Exception as e:
                if initial_load:
                    raise MetricConfigurationError(f"Failed to load initial config: {e}")
                if self.logger:
                    self.logger.error(f"Failed to reload configuration: {e}")

    def register_reload_callback(self, callback: callable) -> None:
        """Register a callback to be called when configuration is reloaded."""
        self.on_config_reload = callback

    def _merge_with_defaults(self, defaults: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Simple merge of override values with defaults."""
        result = deepcopy(defaults)
        for key, value in override.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._merge_with_defaults(result[key], value)
            else:
                result[key] = deepcopy(value)
        return result

    def _validate_exporter_section(self, config: Dict[str, Any]) -> None:
        """Basic validation of exporter configuration."""
        if not config:
            return

        if 'metrics_port' in config:
            metrics_port = config['metrics_port']
            if not isinstance(metrics_port, int) or metrics_port < 1 or metrics_port > 65535:
                raise MetricConfigurationError(f"Invalid metrics_port {metrics_port}")
                
        if 'health_port' in config:
            health_port = config['health_port']
            if not isinstance(health_port, int) or health_port < 1 or health_port > 65535:
                raise MetricConfigurationError(f"Invalid health_port {health_port}")
                
            if 'metrics_port' in config and metrics_port == health_port:
                raise MetricConfigurationError("metrics_port and health_port must be different")


    def _validate_services(self, services_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate services section with optimistic parsing."""
        if not isinstance(services_config, dict):
            raise MetricConfigurationError("Services section must be a dictionary")
            
        validated_services = {}
        
        for service_name, service_config in services_config.items():
            try:
                validated_service = self._validate_service(service_name, service_config)
                if validated_service:
                    validated_services[service_name] = validated_service
                    self._validation_stats['services']['valid'] += 1
                else:
                    self._validation_stats['services']['invalid'] += 1
            except Exception as e:
                self._validation_stats['services']['invalid'] += 1
                if self.logger:
                    self.logger.warning(
                        f"Failed to validate service '{service_name}': {e}. "
                        "Skipping this service but continuing with others."
                    )

        if not validated_services:
            raise MetricConfigurationError("No valid services found in configuration")
            
        return validated_services

    def _validate_service(
        self,
        service_name: str,
        service_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Validate service configuration."""
        if not isinstance(service_config, dict):
            raise MetricConfigurationError(
                f"Service '{service_name}' configuration must be a dictionary"
            )

        validated = {}
        
        # Copy basic service properties
        for key in ['description', 'run_as']:
            if key in service_config:
                validated[key] = service_config[key]

        # Handle metric groups
        if 'metric_groups' not in service_config:
            raise MetricConfigurationError(
                f"No metric groups defined for service '{service_name}'"
            )

        validated['metric_groups'] = {}
        
        for group_name, group_config in service_config['metric_groups'].items():
            try:
                validated_group = self._validate_metric_group(
                    service_name, 
                    group_name, 
                    group_config
                )
                if validated_group:
                    validated['metric_groups'][group_name] = validated_group
                    self._validation_stats['groups']['valid'] += 1
                else:
                    self._validation_stats['groups']['invalid'] += 1
            except Exception as e:
                self._validation_stats['groups']['invalid'] += 1
                if self.logger:
                    self.logger.warning(
                        f"Failed to validate group '{group_name}' in service '{service_name}': {e}"
                    )

        if not validated['metric_groups']:
            raise MetricConfigurationError(f"No valid metric groups in service '{service_name}'")
            
        return validated

    def _validate_metric_group(
        self,
        service_name: str,
        group_name: str,
        group_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Validate metric group configuration."""
        self.logger.verbose(f"=== Validating metric group {group_name} in service {service_name} ===")
        self.logger.verbose(f"Raw group config: {json.dumps(group_config, indent=2)}")

        if not isinstance(group_config, dict):
            raise MetricConfigurationError("Must be a dictionary")

        validated = {'metrics': {}}
        
        # Determine group type
        group_type = MetricGroupType.from_config(group_config)
        self.logger.verbose(f"Group type determined as: {group_type.value}")
        validated['type'] = group_type.value
        
        # Get group content type and validate filters (for dynamic groups only)
        if group_type == MetricGroupType.DYNAMIC:
            content_type = ContentType(group_config.get('content_type', 'text'))
            if 'command' not in group_config:
                raise MetricConfigurationError("Dynamic metric group must specify a command")
            validated['command'] = group_config['command']

            # Validate and store group-level labels if present
            validated_group_labels = {}
            if 'labels' in group_config:
                self.logger.verbose(f"Processing group-level labels for {group_name}")
                self.logger.verbose(f"Group labels config: {json.dumps(group_config['labels'], indent=2)}")
                
                for label_name, label_config in group_config['labels'].items():
                    if not isinstance(label_config, dict):
                        raise MetricConfigurationError(f"Group label {label_name} configuration must be a dictionary")
                    if 'filter' not in label_config:
                        raise MetricConfigurationError(f"Group label {label_name} must specify a filter")
                    if not content_type.validate_filter(label_config['filter']):
                        raise MetricConfigurationError(
                            f"Invalid filter format for {content_type.value} content type "
                            f"in group label '{label_name}': {label_config['filter']}"
                        )
                    validated_group_labels[label_name] = {
                        'filter': label_config['filter'],
                        'content_type': content_type.value
                    }
                
                self.logger.verbose(f"Validated group labels: {json.dumps(validated_group_labels, indent=2)}")
                validated['labels'] = validated_group_labels

            # Pre-validate all metric filters before detailed processing
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                if 'filter' in metric_config:
                    if not content_type.validate_filter(metric_config['filter']):
                        raise MetricConfigurationError(
                            f"Invalid filter format for {content_type.value} content type "
                            f"in metric '{metric_name}': {metric_config['filter']}"
                        )
                        
                # Check metric labels too
                if 'labels' in metric_config:
                    for label_name, label_config in metric_config['labels'].items():
                        if not content_type.validate_filter(label_config['filter']):
                            raise MetricConfigurationError(
                                f"Invalid filter format for {content_type.value} content type "
                                f"in metric '{metric_name}' label '{label_name}': {label_config['filter']}"
                            )
        
        # Process static metrics
        if group_type == MetricGroupType.STATIC:
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                try:
                    # Ensure no metric_type is specified for static metrics
                    if 'type' in metric_config:
                        raise MetricConfigurationError(
                            f"Static metric '{metric_name}' should not specify a type - "
                            "it is implied by the static metric group"
                        )
                    
                    if 'description' not in metric_config:
                        raise MetricConfigurationError("Missing required field: description")
                    if 'value' not in metric_config:
                        raise MetricConfigurationError("Static metric must specify a value")
                    
                    validated['metrics'][metric_name] = {
                        'description': metric_config['description'],
                        'value': float(metric_config['value'])
                    }
                    # Add group labels to static metrics if present
                    if 'labels' in validated:
                        validated['metrics'][metric_name]['group_labels'] = validated['labels']
                except Exception as e:
                    self.logger.error(f"Failed to validate static metric {metric_name}: {e}")
                    raise
        
        else:  # DYNAMIC
            # Validate dynamic metrics
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                try:
                    # Ensure no static metrics in dynamic groups
                    if metric_config.get('type', '').lower() == 'static':
                        raise MetricConfigurationError(
                            f"Static metric '{metric_name}' found in dynamic group '{group_name}'. "
                            "Static metrics must be placed in a static metric group"
                        )
                    
                    metric_type = MetricType.from_config(metric_config)
                    if 'description' not in metric_config:
                        raise MetricConfigurationError("Missing required field: description")
                    if 'filter' not in metric_config:
                        raise MetricConfigurationError(f"{metric_type.value} metric must specify a filter")
                    
                    validated_metric = {
                        'type': metric_type.value,
                        'description': metric_config['description'],
                        'filter': metric_config['filter'],
                        'content_type': content_type.value
                    }
                    
                    # Add group labels first if they exist
                    if 'labels' in validated:
                        self.logger.verbose(f"Adding group labels to metric {metric_name}")
                        validated_metric['group_labels'] = validated['labels']
                    
                    # Handle transforms for dynamic metrics only
                    if 'transform' in metric_config:
                        if not isinstance(metric_config['transform'], str) or not metric_config['transform'].strip():
                            raise MetricConfigurationError("Transform must be a non-empty string")
                        validated_metric['transform'] = metric_config['transform']
                    
                    # Handle metric-specific labels
                    if 'labels' in metric_config:
                        self.logger.verbose(f"Processing metric-specific labels for {metric_name}")
                        validated_labels = {}
                        for label_name, label_config in metric_config['labels'].items():
                            if not isinstance(label_config, dict):
                                raise MetricConfigurationError(f"Label {label_name} configuration must be a dictionary")
                            if 'filter' not in label_config:
                                raise MetricConfigurationError(f"Label {label_name} must specify a filter")
                            validated_labels[label_name] = {
                                'filter': label_config['filter'],
                                'content_type': content_type.value
                            }
                        validated_metric['labels'] = validated_labels
                        self.logger.verbose(f"Added metric-specific labels: {json.dumps(validated_labels, indent=2)}")
                    
                    validated['metrics'][metric_name] = validated_metric
                    
                except Exception as e:
                    self.logger.error(f"Failed to validate metric {metric_name}: {e}")
                    raise

        metric_count = len(validated['metrics'])
        self.logger.verbose(f"Successfully validated {metric_count} metrics in group {group_name}")
        self.logger.verbose(f"Final validated config: {json.dumps(validated, indent=2)}")

        if not validated['metrics']:
            raise MetricConfigurationError("No valid metrics defined")
            
        return validated

    def _validate_metric(
        self,
        service_name: str,
        group_name: str,
        metric_name: str,
        metric_config: Dict[str, Any],
        group_labels: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Validate individual metric configuration."""
        self.logger.verbose(f"=== Starting validation of metric {metric_name} ===")
        self.logger.verbose(f"Raw metric config: {json.dumps(metric_config, indent=2)}")
        if group_labels:
            self.logger.verbose(f"Group labels present: {json.dumps(group_labels, indent=2)}")
        
        if not isinstance(metric_config, dict):
            raise MetricConfigurationError("Must be a dictionary")

        validated = {}
        
        # Validate required fields
        if 'type' not in metric_config:
            raise MetricConfigurationError("Missing required field: type")
        
        metric_type = MetricType.from_config(metric_config)
        self.logger.verbose(f"Metric type validated as: {metric_type}")
            
        if 'description' not in metric_config:
            raise MetricConfigurationError("Missing required field: description")

        validated['type'] = metric_config['type']
        validated['description'] = metric_config['description']

        # Add group labels first if present
        if group_labels:
            self.logger.verbose("Adding group labels to metric")
            validated['group_labels'] = group_labels

        # Validate metric-specific labels if present
        if 'labels' in metric_config:
            self.logger.verbose(f"Processing metric-specific labels")
            self.logger.verbose(f"Label config: {json.dumps(metric_config['labels'], indent=2)}")
            if not isinstance(metric_config['labels'], dict):
                raise MetricConfigurationError("Labels must be a dictionary")
        
            validated_labels = {}
            for label_name, label_config in metric_config['labels'].items():
                if not isinstance(label_config, dict):
                    raise MetricConfigurationError(f"Label {label_name} configuration must be a dictionary")
                
                if 'filter' not in label_config:
                    raise MetricConfigurationError(f"Label {label_name} must specify a filter")
                
                validated_labels[label_name] = {
                    'filter': label_config['filter'],
                    'content_type': label_config.get('content_type', 'text')
                }
            
            validated['labels'] = validated_labels
            self.logger.verbose(f"Added metric-specific labels: {json.dumps(validated_labels, indent=2)}")

        try:
            if metric_type == MetricType.STATIC:
                self.logger.verbose(f"Validating static metric")
                if 'value' not in metric_config:
                    raise MetricConfigurationError("Static metric must specify a value")
                validated['value'] = float(metric_config['value'])
                self.logger.verbose(f"Static metric value validated: {validated['value']}")
            else:  # gauge or counter
                self.logger.verbose(f"Validating dynamic metric")
                if 'filter' not in metric_config:
                    raise MetricConfigurationError(
                        f"{metric_type.value} metric must specify a filter"
                    )
                validated['filter'] = metric_config['filter']

            # Copy optional content_type if present
            if 'content_type' in metric_config:
                validated['content_type'] = metric_config['content_type']

            self.logger.verbose(f"Final validated metric config: {json.dumps(validated, indent=2)}")
            return validated

        except Exception as e:
            self.logger.error(f"Error validating metric {metric_name}: {e}", exc_info=True)
            raise MetricConfigurationError(f"Invalid metric configuration: {e}")

    def _log_validation_summary(self, initial_load: bool) -> None:
        """Log validation statistics summary."""
        if not self.logger:
            return
            
        stats = self._validation_stats
        
        # Calculate totals
        total_services = stats['services']['valid'] + stats['services']['invalid']
        total_groups = stats['groups']['valid'] + stats['groups']['invalid']
        total_metrics = stats['metrics']['valid'] + stats['metrics']['invalid']
        
        if initial_load:
            self.logger.info(
                f"Initial configuration loaded with "
                f"{stats['services']['valid']}/{total_services} services, "
                f"{stats['groups']['valid']}/{total_groups} groups, "
                f"{stats['metrics']['valid']}/{total_metrics} metrics valid"
            )
        else:
            if stats['services']['invalid'] > 0 or stats['groups']['invalid'] > 0:
                self.logger.warning(
                    f"Configuration reloaded with validation issues: "
                    f"{stats['services']['invalid']} invalid services, "
                    f"{stats['groups']['invalid']} invalid groups, "
                    f"{stats['metrics']['invalid']} invalid metrics"
                )
            else:
                self.logger.info(
                    f"Configuration reloaded successfully with "
                    f"{stats['services']['valid']} services, "
                    f"{stats['groups']['valid']} groups, "
                    f"{stats['metrics']['valid']} metrics"
                )

    def _check_reload(self) -> None:
        """Check if config file has been modified and reload if needed."""
        try:
            current_mtime = self._source.config_path.stat().st_mtime
            if current_mtime > self._last_load_time:
                self.load()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to check configuration reload: {e}")

    @staticmethod
    def now_utc() -> datetime:
        """Get current UTC datetime."""
        return datetime.now(timezone.utc)

    def get_uptime_seconds(self) -> float:
        """Get service uptime in seconds."""
        return (self.now_utc() - self._start_time).total_seconds()

    @property
    def exporter_user(self) -> str:
        """Get exporter user."""
        return self.exporter.get('user', self.DEFAULT_EXPORTER_USER)

    @property
    def running_under_systemd(self) -> bool:
        """Check if running under systemd."""
        return self._running_under_systemd

    @property
    def collection_timeout(self) -> int:
        """Get collection timeout in seconds."""
        return self.collection.get('collection_timeout_sec', self.DEFAULT_COLLECTION_TIMEOUT)

    @property
    def exporter(self) -> Dict[str, Any]:
        """Get exporter configuration."""
        self._check_reload()
        return self._config['exporter']
    
    @property
    def services(self) -> Dict[str, Any]:
        """Get services configuration."""
        self._check_reload()
        return self._config['services']

    @property
    def logging(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.exporter.get('logging', {})

    @property
    def collection(self) -> Dict[str, Any]:
        """Get collection configuration."""
        return self.exporter.get('collection', {})
    
    @property
    def metrics_port(self) -> int:
        """Get metrics port number."""
        return self.exporter.get('metrics_port', self.DEFAULT_METRICS_PORT)
    
    @property
    def health_port(self) -> int:
        """Get health check port number."""
        return self.exporter.get('health_port', self.DEFAULT_HEALTH_PORT)
    
    @property
    def poll_interval(self) -> int:
        """Get polling interval in seconds."""
        return self.collection.get('poll_interval_sec', self.DEFAULT_POLL_INTERVAL)
    
    @property
    def max_workers(self) -> int:
        """Get maximum number of worker threads."""
        return self.collection.get('max_workers', self.DEFAULT_MAX_WORKERS)
    
    @property
    def failure_threshold(self) -> int:
        """Get failure threshold count."""
        return self.collection.get('failure_threshold', self.DEFAULT_FAILURE_THRESHOLD)

    def get_service(self, name: str) -> Optional[Dict[str, Any]]:
        """Get service configuration by name."""
        self._check_reload()
        return self.services.get(name)

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ProgramLogger:
    """Manages logging configuration and setup."""
    
    # Verbose logging config
    VERBOSE_LEVEL = 15  # Between DEBUG (10) and INFO (20)

    class VerboseLogger(logging.Logger):
        """Enhanced Logger class adding verbose debugging capabilities."""

        def verbose(
            self,
            msg: Union[str, Callable[[], str]],
            *args: Any,
            **kwargs: Any
        ) -> None:
            """Log verbose debug messages."""
            if not VERBOSE_DEBUG:
                return

            try:
                # Get caller's context
                frame = inspect.currentframe()
                if frame and frame.f_back:
                    caller_frame = frame.f_back
                    module_name = caller_frame.f_globals.get('__name__', '')
                    function_name = caller_frame.f_code.co_name
                    line_no = caller_frame.f_lineno
                    
                    # Add context to message instead of trying to modify LogRecord
                    context = f"[{module_name}.{function_name}:{line_no}] "
                    
                    # Handle message
                    if callable(msg):
                        final_msg = msg(*args) if args else msg()
                    else:
                        final_msg = msg.format(*args) if args else msg
                        
                    self.log(ProgramLogger.VERBOSE_LEVEL, context + str(final_msg), **kwargs)
                    
            except Exception as e:
                # Fallback to basic logging if context extraction fails
                self.warning(f"Failed to get caller context: {e}")
                if callable(msg):
                    self.log(ProgramLogger.VERBOSE_LEVEL, msg(*args) if args else msg(), **kwargs)
                else:
                    self.log(ProgramLogger.VERBOSE_LEVEL, msg, *args, **kwargs)
                    
            finally:
                # Clean up frame references
                if frame:
                    del frame

    def __init__(self, source: ProgramSource, config: ProgramConfig):
        """Initialize logging configuration."""
        # Set VerboseLogger as the default logger class
        logging.addLevelName(self.VERBOSE_LEVEL, 'VERBOSE')
        logging.setLoggerClass(self.VerboseLogger)

        self.source = source
        self.config = config
        self._handlers: Dict[str, logging.Handler] = {}

        # Ensure log file exists and is owned by exporter user
        log_path = self.source.script_dir / f"{self.source.base_name}.log"
        if not log_path.exists():
            user_context = UserContext(self.config.exporter_user, None)
            try:
                with user_context.temp_context():
                    log_path.touch()
                    # Ensure mode is 0o644 (rw-r--r--)
                    log_path.chmod(0o644)
            except Exception as e:
                print(f"Failed to create log file as {self.config.exporter_user}: {e}", file=sys.stderr)
                # Fallback to creating as current user
                log_path.touch()
                log_path.chmod(0o644)
        
        self._logger = self._setup_logging()
        
        # Attach logger to config after setup
        self.config.logger = self._logger

    @property
    def logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self._logger
        
    @property
    def level(self) -> str:
        """Get current log level."""
        return logging.getLevelName(self._logger.level)
    
    @property
    def handlers(self) -> Dict[str, logging.Handler]:
        """Get dictionary of configured handlers."""
        return self._handlers

    def _get_logging_config(self) -> Dict[str, Any]:
        """Safely get logging configuration with defaults.
        
        Returns a complete logging configuration dictionary, using values from:
        1. User configuration in YAML file
        2. ProgramConfig default values
        """
        try:
            exporter_config = self.config._config.get('exporter', {})
            logging_config = exporter_config.get('logging', {})
            
            return {
                'level': logging_config.get('level', self.config.DEFAULT_LOG_LEVEL),
                'file_level': logging_config.get('file_level', self.config.DEFAULT_LOG_FILE_LEVEL),
                'console_level': logging_config.get('console_level', self.config.DEFAULT_LOG_CONSOLE_LEVEL),
                'journal_level': logging_config.get('journal_level', self.config.DEFAULT_LOG_JOURNAL_LEVEL),
                'max_bytes': logging_config.get('max_bytes', self.config.DEFAULT_LOG_MAX_BYTES),
                'backup_count': logging_config.get('backup_count', self.config.DEFAULT_LOG_BACKUP_COUNT),
                'format': logging_config.get('format', self.config.DEFAULT_LOG_FORMAT),
                'date_format': logging_config.get('date_format', self.config.DEFAULT_LOG_DATE_FORMAT)
            }
        except Exception as e:
            # If there's any error, return defaults from ProgramConfig
            return {
                'level': self.config.DEFAULT_LOG_LEVEL,
                'file_level': self.config.DEFAULT_LOG_FILE_LEVEL,
                'console_level': self.config.DEFAULT_LOG_CONSOLE_LEVEL,
                'journal_level': self.config.DEFAULT_LOG_JOURNAL_LEVEL,
                'max_bytes': self.config.DEFAULT_LOG_MAX_BYTES,
                'backup_count': self.config.DEFAULT_LOG_BACKUP_COUNT,
                'format': self.config.DEFAULT_LOG_FORMAT,
                'date_format': self.config.DEFAULT_LOG_DATE_FORMAT
            }

    def _get_formatter(self) -> logging.Formatter:
        """Create formatter using current settings.
        
        Returns:
            Configured logging.Formatter instance
        """
        log_settings = self._get_logging_config()
        return logging.Formatter(
            log_settings['format'],
            log_settings['date_format']
        )

    def _setup_logging(self) -> logging.Logger:
        """Set up logging with configuration from config file.
        
        Creates and configures:
        - Base logger
        - File handler with rotation
        - Console handler
        - Journal handler (if running under systemd)
        
        Returns:
            Configured logging.Logger instance
        
        Note:
            If handler setup fails, ensures at least basic console logging
            is available as a fallback.
        """
        logger = logging.getLogger(self.source.logger_name)
        logger.handlers.clear()

        log_settings = self._get_logging_config()
        logger.setLevel(log_settings['level'])
        
        formatter = logging.Formatter(
            log_settings['format'],
            log_settings['date_format']
        )
        
        try:
            # File handler
            file_handler = RotatingFileHandler(
                self.source.log_path,
                maxBytes=log_settings['max_bytes'],
                backupCount=log_settings['backup_count']
            )
            file_handler.setLevel(log_settings['file_level'])
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            self._handlers['file'] = file_handler
            
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_settings['console_level'])
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            self._handlers['console'] = console_handler
            
            # Journal handler for systemd
            if self.config.running_under_systemd:
                journal_handler = journal.JournaldLogHandler()
                journal_handler.setLevel(log_settings['journal_level'])
                journal_handler.setFormatter(formatter)
                logger.addHandler(journal_handler)
                self._handlers['journal'] = journal_handler

        except Exception as e:
            # If handler setup fails, ensure we have at least a basic console handler
            if not logger.handlers:
                basic_handler = logging.StreamHandler(sys.stdout)
                basic_handler.setFormatter(logging.Formatter(self.config.DEFAULT_LOG_FORMAT))
                logger.addHandler(basic_handler)
                self._handlers['console'] = basic_handler
                print(f"Failed to setup handlers: {e}, using basic console handler", file=sys.stderr)
        
        return logger

    def set_level(self, level: Union[str, int]) -> None:
        """Set log level for all handlers.
        
        Args:
            level: New log level (can be string name or integer constant)
        """
        self._logger.setLevel(level)
        for handler in self._logger.handlers:
            handler.setLevel(level)
            
    def add_handler(
        self,
        name: str,
        handler: logging.Handler,
        level: Optional[Union[str, int]] = None
    ) -> None:
        """Add a new handler to the logger.
        
        Args:
            name: Identifier for the handler
            handler: The handler instance to add
            level: Optional specific level for this handler
        """
        if level is not None:
            handler.setLevel(level)
        handler.setFormatter(self._get_formatter())
        self._logger.addHandler(handler)
        self._handlers[name] = handler
    
    def remove_handler(self, name: str) -> None:
        """Remove a handler by name.
        
        Args:
            name: Identifier of handler to remove
        """
        if name in self._handlers:
            self._logger.removeHandler(self._handlers[name])
            del self._handlers[name]

    def update_config(self) -> None:
        """Update logging configuration from current config settings.
        
        Reloads all logging settings from config and updates existing handlers.
        """
        log_settings = self._get_logging_config()
        formatter = self._get_formatter()
        
        self._logger.setLevel(log_settings['level'])
        
        # Update existing handlers
        for name, handler in self._handlers.items():
            handler.setFormatter(formatter)
            if name == 'file':
                handler.setLevel(log_settings['file_level'])
            elif name == 'console':
                handler.setLevel(log_settings['console_level'])
            elif name == 'journal':
                handler.setLevel(log_settings['journal_level'])

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricGroupType(Enum):
    """Types of metric groups supported."""
    STATIC = "static"     # Group containing only static values
    DYNAMIC = "dynamic"   # Group requiring command execution

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'MetricGroupType':
        """Get metric group type from config."""
        if 'type' in config:
            try:
                return cls(config['type'].lower())
            except ValueError:
                raise MetricConfigurationError(
                    f"Invalid metric group type: {config['type']}. "
                    f"Must be one of: {[t.value for t in cls]}"
                )
        
        # Default to dynamic if not specified
        return cls.DYNAMIC
    
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricType(Enum):
    """Types of metrics supported for dynamic groups."""
    GAUGE = "gauge"      # A value that can go up and down
    COUNTER = "counter"  # Value that only increases

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'MetricType':
        """Get metric type from config."""
        if 'type' not in config:
            raise MetricConfigurationError("Dynamic metrics must specify a type")
            
        try:
            return cls(config['type'].lower())
        except ValueError:
            raise MetricConfigurationError(
                f"Invalid metric type: {config['type']}. "
                f"Must be one of: {[t.value for t in cls]}"
            )

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

@dataclass(frozen=True, eq=True)
class MetricLabel:
    """Label definition for metrics."""
    name: str
    value: Optional[str] = None
    filter: Optional[str] = None
    content_type: str = "text"

@dataclass(frozen=True, eq=True)
class MetricIdentifier:
    """Structured metric identifier."""
    service: str
    group: str
    name: str
    group_type: MetricGroupType
    description: str
    type: Optional[MetricType] = None
    labels: Tuple[MetricLabel, ...] = field(default_factory=tuple)  # Note: Tuple instead of tuple

    def __hash__(self) -> int:
        """Explicit hash implementation to ensure consistency with labels."""
        label_tuples = tuple(
            (label.name, label.value or '') 
            for label in sorted(self.labels, key=lambda x: x.name)
        )
        return hash((
            self.service,
            self.group, 
            self.name,
            self.group_type,
            self.description,
            self.type,
            label_tuples
        ))

    @property
    def prometheus_name(self) -> str:
        """Get prometheus-compatible metric name."""
        return f"{self.service}_{self.group}_{self.name}"

    def get_label_dict(self) -> Dict[str, str]:
        """Get labels as a dictionary for Prometheus."""
        sorted_labels = sorted(self.labels, key=lambda x: x.name)
        return {label.name: (label.value or '') for label in sorted_labels}

    def get_debug_info(self) -> str:
        """Get detailed string representation for debugging."""
        parts = [
            f"name='{self.prometheus_name}'",
            f"type={self.type.value if self.type else 'static'}",
            f"group_type={self.group_type.value}"
        ]
        
        if self.labels:
            label_strs = [
                f"{label.name}='{label.value or ''}'"
                for label in sorted(self.labels, key=lambda x: x.name)
            ]
            parts.append(f"labels=[{', '.join(label_strs)}]")
            
        return f"MetricIdentifier({', '.join(parts)})"

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ContentType(Enum):
    """Content types for data sources."""
    TEXT = "text" # Use regex pattern matching
    JSON = "json" # Use jq-style path filtering
    
    def validate_filter(self, filter_expr: str, logger: Optional[logging.Logger] = None) -> bool:
        """Validate filter expression matches content type."""
        try:
            if self == ContentType.TEXT:
                if logger:
                    logger.debug(f"Validating TEXT filter: {filter_expr}")
                re.compile(filter_expr)
                return True
            elif self == ContentType.JSON:
                if logger:
                    logger.debug(f"Validating JSON filter: {filter_expr}")
                # jq-style path should be dot-separated keys
                return bool(re.match(r'^\.?[\w]+(\.[\w]+)*$', filter_expr))
        except Exception as e:
            if logger:
                logger.warning(f"Filter validation failed: {e}")
            return False
        return False  # Only hit if it's not TEXT or JSON

    def parse_value(self, content: str, filter_expr: str, logger: logging.Logger, convert_to_float: bool = True) -> Optional[Union[float, str]]:
        """Parse content based on content type."""
        try:
            if not content or not filter_expr:
                logger.verbose("Empty content or filter")
                return None

            if self == ContentType.TEXT:
                logger.verbose(f"Applying pattern: {filter_expr}")
                match = re.search(filter_expr, content)
                if not match:
                    logger.verbose(f"No match found for pattern")
                    return None
                value = match.group(1)
                
            elif self == ContentType.JSON:
                try:
                    data = json.loads(content)
                    path_parts = filter_expr.strip('.').split('.')
                    current_data = data
                    
                    for key in path_parts:
                        if not isinstance(current_data, dict):
                            logger.verbose(f"JSON path error: value at '{key}' is not an object")
                            return None
                        if key not in current_data:
                            logger.verbose(f"JSON path error: key '{key}' not found")
                            return None
                        current_data = current_data[key]
                    value = current_data
                except json.JSONDecodeError:
                    logger.verbose("Invalid JSON content")
                    return None
            else:
                logger.warning(f"Unsupported content type: {self.value}")
                return None

            # Special handling for boolean values
            if isinstance(value, bool) or str(value).lower() in ('true', 'false'):
                if not convert_to_float:
                    return str(value).lower()
                return 1.0 if str(value).lower() == 'true' else 0.0

            # Convert to float if needed
            if convert_to_float:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    logger.verbose(f"Could not convert '{value}' to float")
                    return None

            return str(value)

        except Exception as e:
            logger.verbose(f"Parse error: {str(e)}")
            return None

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

@dataclass
class CollectionResult:
    """Result of metric collection attempt."""
    success: bool
    value: Optional[float] = None
    error: Optional[str] = None

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

@dataclass
class CollectionStats:
    """Statistics for metric collection operations.
    
    Tracks metrics collection success/failure rates and timing information
    for health monitoring and operational visibility.
    
    Attributes:
        attempts (int): Total collection attempts
        successful (int): Successful collections
        warnings (int): Collection warnings
        errors (int): Collection errors
        consecutive_failures (int): Current streak of failures
        last_collection_time (float): Duration of last collection
        total_collection_time (float): Cumulative collection time
        last_collection_datetime (datetime): Timestamp of last collection
    """
    attempts: int = 0
    successful: int = 0
    warnings: int = 0
    errors: int = 0
    consecutive_failures: int = 0
    last_collection_time: float = 0
    total_collection_time: float = 0
    last_collection_datetime: datetime = field(
        default_factory=lambda: ProgramConfig.now_utc()
    )

    def reset(self):
        """Reset all statistics to initial values."""
        self.attempts = 0
        self.successful = 0
        self.warnings = 0
        self.errors = 0
        self.consecutive_failures = 0
        self.last_collection_time = 0
        self.total_collection_time = 0
        self.last_collection_datetime = ProgramConfig.now_utc()
    
    def update_collection_time(self, start_time: float):
        """Update collection timing statistics."""
        collection_time = ProgramConfig.now_utc().timestamp() - start_time
        self.last_collection_time = collection_time
        self.total_collection_time += collection_time
        self.last_collection_datetime = ProgramConfig.now_utc()
    
    def get_average_collection_time(self) -> float:
        """Calculate average collection time."""
        return self.total_collection_time / self.attempts if self.attempts > 0 else 0
    
    def is_healthy(self, threshold: int) -> bool:
        """Determine if collection statistics indicate healthy operation."""
        return self.consecutive_failures < threshold

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

@dataclass
class CommandResult:
    """Result of a command execution."""
    output: Optional[str]
    success: bool
    error_message: Optional[str] = None
    execution_time: float = 0
    timestamp: datetime = field(default_factory=ProgramConfig.now_utc)

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# User Management
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ServiceUserManager:
    """Manages service users and sudo permissions."""

    def __init__(self, config: ProgramConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.source = config._source
        self.service_users: set[str] = set()
        self.exporter_user = config.exporter_user

    def collect_service_users(self) -> set[str]:
        """Collect all unique service users from configuration."""
        users = {self.exporter_user}
        
        for service_config in self.config.services.values():
            if 'run_as' in service_config:
                users.add(service_config['run_as'])
        
        self.service_users = users
        return users

    def generate_sudoers_content(self) -> str:
        """Generate sudoers file content with unrestricted command access.
    
        Note: Security is maintained through proper system user permissions
        rather than command restrictions. Each service user should be
        configured with appropriate system-level access controls.
        """
        content = [
            "# Auto-generated by Prometheus Metrics Exporter",
            "# Do not edit manually - changes will be overwritten",
            f"# Generated at {self.config.now_utc().isoformat()}",
            "",
            "# Security Note:",
            "# Access control is managed through system user permissions",
            "# Each service user should have appropriate system-level restrictions",
            f"# The {self.exporter_user} user can only run commands as defined service users",
            ""
        ]

        for user in sorted(self.service_users - {self.exporter_user}):
            content.append(f"{self.exporter_user} ALL=({user}) NOPASSWD: ALL")

        return "\n".join(content) + "\n"

    def update_sudo_permissions(self) -> bool:
        """Update sudoers configuration for service users."""
        try:
            if os.geteuid() != 0:
                self.logger.error("Must be root to update sudo permissions")
                return False

            sudoers_path = self.source.sudoers_path
            temp_path =f"{sudoers_path}.tmp"
            
            content = self.generate_sudoers_content()
            
            with open(temp_path, 'w') as f:
                f.write(content)
            
            os.chmod(temp_path, 0o440)
            
            result = subprocess.run(['visudo', '-c', '-f', temp_path], capture_output=True)
            if result.returncode != 0:
                self.logger.error(f"Invalid sudoers syntax: {result.stderr.decode()}")
                os.unlink(temp_path)
                return False
            
            os.rename(temp_path, sudoers_path)
            self.logger.info(f"Updated sudo permissions for users: {', '.join(sorted(self.service_users))}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to update sudo permissions: {e}")
            return False

    def verify_user_exists(self, username: str) -> bool:
        """Verify if a system user exists."""
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            return False

    def ensure_users_exist(self) -> bool:
        """Verify all required users exist in the system."""
        missing_users = []
        
        for username in self.service_users:
            if not self.verify_user_exists(username):
                missing_users.append(username)
        
        if missing_users:
            self.logger.error(f"Missing required users: {', '.join(missing_users)}")
            return False
            
        return True

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class UserContext:
    """Manages user context for command execution."""
    
    def __init__(self, username: str, logger: logging.Logger):
        self.logger = logger
        self._original_uid = os.getuid()
        self._original_gid = os.getgid()
        self._enabled = self._original_uid == 0
        
        self.username = username
        
        try:
            self.user_info = pwd.getpwnam(self.username)
            self.group_info = grp.getgrgid(self.user_info.pw_gid)
        except KeyError as e:
            if self.logger:
                self.logger.error(f"Invalid user or group: {e}")
            self._enabled = False
    
    @contextmanager
    def temp_context(self):
        """Temporarily switch user context if running as root."""
        if not self._enabled:
            if self.logger:
                self.logger.warning(
                    f"User switching disabled (not running as root). "
                    f"Commands will run as current user."
                )
            yield
            return

        try:
            if self.logger:
                self.logger.debug(f"Switching to user {self.username} (uid={self.user_info.pw_uid})")
            
            os.setegid(self.group_info.gr_gid)
            os.seteuid(self.user_info.pw_uid)
            
            try:
                yield
            finally:
                os.seteuid(self._original_uid)
                os.setegid(self._original_gid)
                if self.logger:
                    self.logger.debug(f"Restored original user (uid={self._original_uid})")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to switch to user {self.username}: {e}")
            raise
        
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Command Execution
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class CommandExecutor:
    """Executes commands with user context support."""
    
    def __init__(self, config: ProgramConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
    
    async def execute_command(
        self,
        command: str,
        user_context: Optional[UserContext] = None
    ) -> CommandResult:
        """Execute command with optional user context."""
        self.logger.verbose(f"Executing command: {command}")
        start_time = self.config.now_utc().timestamp()
        
        try:
            if user_context:
                with user_context.temp_context():
                    return await self._execute(command)
            else:
                return await self._execute(command)
            
        except Exception as e:
            return CommandResult(
                output=None,
                success=False,
                error_message=str(e),
                execution_time=self.config.now_utc().timestamp() - start_time
            )
    
    async def _execute(self, command: str) -> CommandResult:
        """Execute shell command."""
        start_time = self.config.now_utc().timestamp()
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            execution_time = self.config.now_utc().timestamp() - start_time
            
            if process.returncode == 0:
                return CommandResult(
                    output=stdout.decode().strip(),
                    success=True,
                    execution_time=execution_time
                )
            else:
                return CommandResult(
                    output=None,
                    success=False,
                    error_message=stderr.decode().strip(),
                    execution_time=execution_time
                )
                
        except Exception as e:
            return CommandResult(
                output=None,
                success=False,
                error_message=str(e),
                execution_time=self.config.now_utc().timestamp() - start_time
            )

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Metrics Collection
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class CollectionManager:
    """Manages parallel collection at service and group levels."""
    
    def __init__(self, config: ProgramConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self._semaphore = asyncio.Semaphore(config.max_workers)
    
    async def collect_services(
        self,
        collectors: Dict[str, 'ServiceMetricsCollector']
    ) -> Dict[str, Dict[MetricIdentifier, float]]:
        """Collect metrics from multiple services in parallel."""
        tasks = []
        service_names = []
        
        for service_name, collector in collectors.items():
            self.logger.verbose(f"Creating collection task for service: {service_name}")
            tasks.append(
                self.collect_with_timeout(
                    collector.collect_metrics(),
                    service_name
                )
            )
            service_names.append(service_name)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            name: result for name, result in zip(service_names, results)
            if not isinstance(result, Exception)
        }

    async def collect_with_timeout(
        self,
        coro: Awaitable,
        identifier: str
    ) -> Any:
        """Execute coroutine with timeout and semaphore."""
        try:
            async with self._semaphore:
                return await asyncio.wait_for(coro, timeout=self.config.collection_timeout)
        except asyncio.TimeoutError:
            self.logger.error(f"Collection timed out for {identifier}")
            return None
        except Exception as e:
            self.logger.error(f"Collection failed for {identifier}: {e}")
            return None

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ServiceMetricsCollector:
    """Collects metrics for a specific service."""
    
    def __init__(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        logger: logging.Logger,
        config: ProgramConfig
    ):
        self.service_name = service_name
        self.service_config = service_config
        self.logger = logger
        self.config = config
        self.command_executor = CommandExecutor(self.config, logger)
        
        # Debug log initialization
        self.logger.verbose(f"Initializing collector for service: {service_name}")
        self.logger.verbose(f"Service config: {service_config}")

        # Set up user context if specified
        self.user_context = None
        if 'run_as' in service_config:
            try:
                username = service_config['run_as']
                self.user_context = UserContext(username, logger)
                self.logger.verbose(f"Created user context for {username}")
            except Exception as e:
                self.logger.error(f"Failed to initialize user context for {service_name}: {e}")
    
    async def collect_metrics(self) -> Dict[MetricIdentifier, float]:
        """Collect all metrics for this service."""
        results = {}
        self.logger.info(f"Starting metrics collection for service: {self.service_name}")
        self.logger.info(f"Service config: {self.service_config}")

        metric_groups = self.service_config.get('metric_groups', {})
        self.logger.verbose(f"Found {len(metric_groups)} metric groups")

        for group_name, group_config in metric_groups.items():
            self.logger.info(f"Processing metric group: {group_name}")
            self.logger.info(f"Group config: {group_config}")
            
            try:
                group_type = MetricGroupType.from_config(group_config)
                self.logger.info(f"Group type determined as: {group_type}")
            
                if group_type == MetricGroupType.STATIC:
                    self.logger.info(f"Processing static metric group: {group_name}")
                    # Process static metrics
                    for metric_name, metric_config in group_config.get('metrics', {}).items():
                        try:
                            identifier = MetricIdentifier(
                                service=self.service_name,
                                group=group_name,
                                name=metric_name,
                                group_type=MetricGroupType.STATIC,
                                description=metric_config['description']
                            )
                            value = float(metric_config['value'])
                            results[identifier] = value
                            self.logger.info(f"Added static metric: {identifier.prometheus_name} = {metric_config['value']}")
                        except Exception as e:
                            self.logger.error(f"Failed to process static metric {metric_name}: {e}")
                else:
                    self.logger.verbose(f"Processing dynamic metric group: {group_name}")
                    try:
                        group_metrics = await self.collect_group(group_name, group_config)
                        self.logger.info(f"Group {group_name} collection results: {group_metrics}")
                        results.update(group_metrics)
                    except Exception as e:
                        self.logger.error(f"Failed to collect dynamic metric group {group_name}: {e}", exc_info=True)
            except Exception as e:
                self.logger.error(f"Failed to process group {group_name}: {e}", exc_info=True)
        
        self.logger.verbose(f"Service {self.service_name} final collection results: {results}")
        return results
    
    async def collect_group(
        self,
        group_name: str,
        group_config: Dict
    ) -> Dict[str, tuple[MetricIdentifier, float]]:
        """Collect metrics for a dynamic group."""
        self.logger.verbose(f"=== Starting collection for group {group_name} ===")
        results = {}

        try:
            # Execute command and log output for debugging
            command = group_config['command']
            command_result = await self.command_executor.execute_command(
                command, 
                self.user_context
            )
            
            if not command_result.success:
                self.logger.error(
                    f"Failed to execute command for group {group_name}:\n"
                    f"Command: {command}\n"
                    f"Error: {command_result.error_message}"
                )
                return results

            # Log command output at verbose level for debugging
            self.logger.verbose(
                f"Command output for {group_name}:\n"
                f"{command_result.output}"
            )

            # Get group content type and validate output format
            output = command_result.output
            if not output or not output.strip():
                self.logger.error(f"Command for group {group_name} produced no output")
                return results

            group_content_type = ContentType(group_config.get('content_type', 'text'))
            self.logger.verbose(
                f"Using content type {group_content_type.value} for group {group_name}"
            )

            # Extract group-level labels first
            group_labels = []
            if 'labels' in group_config:
                self.logger.verbose("\n=== Processing group-level labels ===")
                self.logger.verbose(f"Full group config: {json.dumps(group_config, indent=2)}")
                self.logger.verbose(f"Group labels config: {json.dumps(group_config['labels'], indent=2)}")
                extracted_labels = self._extract_label_values(
                    group_config['labels'],
                    output,
                    group_content_type
                )
                group_labels = list(extracted_labels)  # Convert tuple to list for manipulation
                self.logger.verbose(f"Extracted group labels: {group_labels}")

            # Process each metric
            failed_metrics = []
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                try:
                    if 'type' not in metric_config:
                        self.logger.warning(f"Metric {metric_name} missing required type field")
                        continue

                    metric_type = MetricType.from_config(metric_config)
                    raw_value = None
                    
                    try:
                        # First try to extract the raw value
                        raw_value = group_content_type.parse_value(
                            output,
                            metric_config['filter'],
                            self.logger,
                            convert_to_float=False
                        )
                        
                        if raw_value is None:
                            self.logger.verbose(
                                f"No value matched for metric {metric_name} using filter: "
                                f"{metric_config['filter']}"
                            )
                            continue

                        self.logger.verbose(f"Raw value for {metric_name}: {raw_value}")

                        # Handle transforms
                        final_value = raw_value
                        if 'transform' in metric_config:
                            transform = metric_config['transform']
                            try:
                                # Prepare evaluation environment
                                now = datetime.now(timezone.utc).timestamp()
                                env = {
                                    'value': raw_value,
                                    'true': True,
                                    'false': False,
                                    'now': now,
                                    'to_timestamp': lambda dt_str, fmt: datetime.strptime(
                                        dt_str, fmt
                                    ).replace(tzinfo=timezone.utc).timestamp(),
                                    'unix_micro_to_sec': lambda ts: float(ts) / 1_000_000,
                                    'unix_nano_to_sec': lambda ts: float(ts) / 1_000_000_000,
                                    'unix_milli_to_sec': lambda ts: float(ts) / 1_000,
                                }
                                
                                final_value = eval(transform, {'__builtins__': {}}, env)
                                self.logger.verbose(
                                    f"Transform for {metric_name}:\n"
                                    f"Expression: {transform}\n"
                                    f"Input: {raw_value}\n"
                                    f"Result: {final_value}"
                                )
                            except Exception as e:
                                self.logger.warning(
                                    f"Transform failed for metric {metric_name}:\n"
                                    f"Expression: {transform}\n"
                                    f"Input value: {raw_value}\n"
                                    f"Error: {str(e)}"
                                )
                                continue

                        # Convert to float for Prometheus
                        try:
                            metric_value = float(final_value)
                        except (TypeError, ValueError) as e:
                            self.logger.warning(
                                f"Could not convert value for metric {metric_name}:\n"
                                f"Value: {final_value}\n"
                                f"Error: {str(e)}"
                            )
                            continue

                        # Extract metric-specific labels
                        metric_labels = []
                        if 'labels' in metric_config:
                            self.logger.verbose(f"\n=== Processing metric-level labels for {metric_name} ===")
                            self.logger.verbose(f"Metric label config: {json.dumps(metric_config['labels'], indent=2)}")
                            extracted_labels = self._extract_label_values(
                                metric_config['labels'],
                                output,
                                group_content_type
                            )
                            metric_labels = list(extracted_labels)
                            self.logger.verbose(f"Extracted metric labels: {metric_labels}")

                        # Combine group and metric labels
                        combined_labels = []
                        combined_labels.extend(group_labels)  # Start with group labels
                        combined_labels.extend(metric_labels) # Add metric labels
                        self.logger.verbose(f"Final combined labels for {metric_name}: {combined_labels}")

                        # Create identifier with all labels
                        identifier = MetricIdentifier(
                            service=self.service_name,
                            group=group_name,
                            name=metric_name,
                            group_type=MetricGroupType.DYNAMIC,
                            type=metric_type,
                            description=metric_config['description'],
                            labels=tuple(combined_labels)
                        )

                        key = f"{self.service_name}_{group_name}_{metric_name}"
                        results[key] = (identifier, metric_value)
                        
                    except MetricValidationError as e:
                        # Handle validation errors without full stack traces
                        self.logger.verbose(
                            f"Validation failed for metric {metric_name}:\n"
                            f"Filter: {metric_config['filter']}\n"
                            f"Error: {str(e)}"
                        )
                        failed_metrics.append((metric_name, str(e)))
                        continue
                        
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error processing metric {metric_name}: {str(e)}"
                    )
                    failed_metrics.append((metric_name, str(e)))
                    continue

            # Summarize collection results
            if results:
                self.logger.info(
                    f"Successfully collected {len(results)} metrics from group {group_name}"
                )
            if failed_metrics:
                self.logger.warning(
                    f"Failed to collect {len(failed_metrics)} metrics from group {group_name}:\n" +
                    "\n".join(f"- {name}: {error}" for name, error in failed_metrics)
                )

            return results
                
        except Exception as e:
            self.logger.error(f"Failed to collect metric group {group_name}: {str(e)}")
            return {}
    
        # Modify _parse_metric_value:
    def _parse_metric_value(
            self,
            source_data: str,
            metric_config: Dict,
            metric_type: MetricType
        ) -> Optional[float]:
            """Parse individual metric value from group's source data."""
            try:
                if source_data is None:
                    self.logger.verbose("No source data available")
                    return None
                
                if 'filter' not in metric_config:
                    self.logger.error(f"{metric_type.value} metric must specify a filter")
                    return None

                content_type = metric_config.get('content_type', 'text')
                try:
                    content_type_enum = ContentType(content_type)
                    raw_value = content_type_enum.parse_value(
                        source_data,
                        metric_config['filter'],
                        self.logger
                    )
                    if raw_value is None:
                        raise MetricValidationError("Parser returned None value")
                        
                    # Apply transform if specified
                    if 'transform' in metric_config:
                        transform = metric_config['transform']
                        self.logger.verbose(f"Applying transform: {transform}")
                        try:
                            # Safe evaluation environment with type conversion functions
                            now = datetime.now(timezone.utc).timestamp()
                            
                            # Move env out of the nested scope and include all functions
                            transform_env = {
                                '__builtins__': {
                                    'int': int,
                                    'float': float,
                                    'str': str
                                },
                                'value': str(raw_value),
                                'true': 1,
                                'false': 0,
                                'now': now,
                                'to_timestamp': lambda dt_str, fmt: datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc).timestamp(),
                                'unix_micro_to_sec': lambda ts: float(ts) / 1_000_000,
                                'unix_nano_to_sec': lambda ts: float(ts) / 1_000_000_000,
                                'unix_milli_to_sec': lambda ts: float(ts) / 1_000,
                                'RFC3339': '%Y-%m-%dT%H:%M:%S.%fZ',
                                'ISO8601': '%Y-%m-%dT%H:%M:%S%z',
                                'SYSTEMD': '%a %Y-%m-%d %H:%M:%S UTC',
                            }
                            
                            result = eval(transform, transform_env)
                            self.logger.verbose(f"Transform result: {result}")
                            return float(result)
                        except Exception as e:
                            self.logger.error(f"Transform failed: {e}")
                            return None

                    return float(raw_value)  # Final validation that value is numeric
                    
                except (TypeError, ValueError, MetricValidationError) as e:
                    self.logger.warning(
                        f"Failed to validate metric value: {e}. "
                        f"Skipping this metric but continuing collection."
                    )
                    return None
                    
            except Exception as e:
                self.logger.warning(
                    f"Unexpected error parsing metric value: {e}. "
                    f"Skipping this metric but continuing collection."
                )
                return None

    def _extract_label_values(
        self,
        label_definitions: Dict[str, Dict],
        output: str,
        content_type: ContentType
    ) -> tuple[MetricLabel, ...]:
        """Extract label values from command output."""
        if not label_definitions:
            return tuple()
        
        # Debug logging
        self.logger.verbose(f"Extracting labels from:\n{output}")
        self.logger.verbose(f"Label definitions: {json.dumps(label_definitions, indent=2)}")

        labels_list = []
        for label_name, config in sorted(label_definitions.items()):
            try:
                raw_value = content_type.parse_value(
                    output,
                    config['filter'],
                    self.logger,
                    convert_to_float=False  # Important: we want string values
                )
                
                self.logger.verbose(f"Label {label_name}: raw_value={raw_value}")
                
                # Important: Only create label if we got a value
                if raw_value is not None:
                    labels_list.append(MetricLabel(
                        name=label_name,
                        value=str(raw_value).strip(),
                        filter=config['filter']
                    ))
                else:
                    self.logger.warning(f"No value found for label {label_name} with filter {config['filter']}")
            except Exception as e:
                self.logger.error(f"Failed to extract label {label_name}: {e}")

        return tuple(labels_list)

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricsCollector:
    """Main metrics collector managing multiple services."""
    
    def __init__(self, config: ProgramConfig, logger: logging.Logger):
        """Initialize metrics collector with enhanced metric storage.
        
        Args:
            config: Program configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.stats = CollectionStats()
        
        # Service collectors
        self.service_collectors: Dict[str, ServiceMetricsCollector] = {}
        
        # Metric storage with better typing
        self._prometheus_metrics: Dict[str, Union[Gauge, Counter]] = {}
        
        # Store previous values with label-aware keys
        # Key format: "metric_name{label1=value1,label2=value2}"
        self._previous_values: Dict[str, float] = {}
        
        # Debug counters
        self._metric_updates = 0
        self._label_updates = 0
        
        self.collection_manager = CollectionManager(config, logger)
        
        # Register for config reload notifications
        self.config.register_reload_callback(self._reinitialize_collectors)
        
        self.logger.verbose("Initializing metrics collector...")
        self._initialize_collectors()
        self._setup_internal_metrics()
        
        # Log initial state
        self.logger.verbose(
            "Metrics collector initialized:\n"
            f"- Service collectors: {len(self.service_collectors)}\n"
            f"- Prometheus metrics: {len(self._prometheus_metrics)}\n"
            f"- Previous values: {len(self._previous_values)}"
        )
    
    def _initialize_collectors(self):
        """Initialize collectors for each service."""
        for service_name, service_config in self.config.services.items():
            try:
                self.service_collectors[service_name] = ServiceMetricsCollector(
                    service_name,
                    service_config,
                    self.logger,
                    self.config
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to initialize collector for {service_name}: {e}"
                )

    def _setup_internal_metrics(self):
        """Set up internal metrics tracking."""
        self._internal_metrics = {
            'collection_successful': Gauge(
                'exporter_collection_successful_total',
                'Total number of successful metric collections'
            ),
            'collection_errors': Gauge(
                'exporter_collection_errors_total',
                'Total number of metric collection errors'
            ),
            'collection_duration': Gauge(
                'exporter_collection_duration_seconds',
                'Duration of metric collection in seconds'
            ),
            'uptime': Gauge(
                'exporter_uptime_seconds',
                'Time since service start in seconds'
            ),
            'last_collection_unix_seconds': Gauge(
                'exporter_last_collection_unix_seconds',
                'Unix timestamp of last successful metrics collection with millisecond precision'
            )
        }

    def _reinitialize_collectors(self):
        """Reinitialize collectors after config reload."""
        self.logger.info("Reinitializing collectors due to configuration change")
        self.service_collectors.clear()  # Clear existing collectors
        self._initialize_collectors()    # Create new ones with updated config

    def _create_prometheus_metric(
            self,
            identifier: MetricIdentifier
        ) -> Union[Gauge, Counter]:
            """Create appropriate Prometheus metric based on identifier.
            
            Args:
                identifier: Metric identifier containing all metric information
                
            Returns:
                Prometheus metric object (Gauge or Counter) configured with labels
                
            Note:
                Labels must be registered at creation time, even if values aren't set yet.
            """
            try:
                # Debug log the full identifier
                self.logger.verbose(f"\n=== Creating new Prometheus metric ===\n{identifier.get_debug_info()}")
                
                # Get and validate label names
                label_names = []
                if identifier.labels:
                    label_names = [label.name for label in sorted(identifier.labels, key=lambda x: x.name)]
                    self.logger.verbose(f"Registered label names: {label_names}")
                
                # Determine metric class and create instance
                if identifier.group_type == MetricGroupType.STATIC:
                    self.logger.verbose("Creating static Gauge metric")
                    metric = Gauge(
                        identifier.prometheus_name,
                        identifier.description,
                        labelnames=label_names
                    )
                elif identifier.type == MetricType.COUNTER:
                    self.logger.verbose("Creating Counter metric")
                    metric = Counter(
                        identifier.prometheus_name,
                        identifier.description,
                        labelnames=label_names
                    )
                else:
                    self.logger.verbose("Creating dynamic Gauge metric")
                    metric = Gauge(
                        identifier.prometheus_name,
                        identifier.description,
                        labelnames=label_names
                    )
                    
                self.logger.verbose(
                    f"Successfully created metric:\n"
                    f"- Name: {identifier.prometheus_name}\n"
                    f"- Type: {type(metric).__name__}\n"
                    f"- Labels: {label_names}"
                )
                
                return metric
                
            except Exception as e:
                self.logger.error(f"Failed to create metric {identifier.prometheus_name}: {e}", exc_info=True)
                raise

    def _get_metric_key(self, identifier: MetricIdentifier, labels: Optional[Dict[str, str]] = None) -> str:
        """Create unique metric key."""
        key = f"{identifier.service}_{identifier.group}_{identifier.name}"
        if labels:
            # Sort labels for consistent key generation 
            label_str = '_'.join(f"{k}={v}" for k, v in sorted(labels.items()))
            key = f"{key}_{label_str}"
        return key

    def _update_prometheus_metrics(self, metrics: Dict[str, tuple[MetricIdentifier, float]]):
        """Update Prometheus metrics with collected values."""
        self.logger.verbose("\n=== Starting prometheus metrics update ===")
        self.logger.verbose(f"Received {len(metrics)} metrics to update")

        # Log current storage state for debugging
        self.logger.verbose(f"Current storage keys: {list(self._prometheus_metrics.keys())}")

        for key, (identifier, value) in sorted(metrics.items()):
            try:
                self.logger.verbose(f"\n--- Processing metric {identifier.get_debug_info()} ---")
                
                # Create storage key that includes labels
                storage_key = key
                if identifier.labels:
                    label_str = "_".join(f"{l.name}={l.value}" for l in sorted(identifier.labels, key=lambda x: x.name))
                    storage_key = f"{key}_{label_str}"
                self.logger.verbose(f"Using storage key: {storage_key}")
                    
                # Create metric if it doesn't exist
                if storage_key not in self._prometheus_metrics:
                    label_names = [label.name for label in sorted(identifier.labels, key=lambda x: x.name)]
                    self.logger.verbose(f"Creating new metric {storage_key} with labels: {label_names}")
                    metric = self._create_prometheus_metric(identifier)
                    self._prometheus_metrics[storage_key] = metric
                else:
                    metric = self._prometheus_metrics[storage_key]
                    self.logger.verbose(f"Using existing metric {storage_key}")

                if value is not None:
                    try:
                        # Apply labels if present
                        if identifier.labels:
                            label_dict = identifier.get_label_dict()
                            self.logger.verbose(f"Applying labels to metric: {label_dict}")
                            labeled_metric = metric.labels(**label_dict)
                            self.logger.verbose(f"Successfully applied labels to metric")
                            metric = labeled_metric
                            
                        # Update value
                        if isinstance(metric, Counter):
                            prev_value = self._previous_values.get(storage_key, 0)
                            if value > prev_value:
                                increment = value - prev_value
                                self.logger.verbose(
                                    f"Incrementing counter:\n"
                                    f"- Previous: {prev_value}\n"
                                    f"- Current: {value}\n"
                                    f"- Increment: {increment}\n"
                                    f"- Storage key: {storage_key}"
                                )
                                metric.inc(increment)
                            self._previous_values[storage_key] = value
                        else:
                            self.logger.verbose(f"Setting gauge value: {value}")
                            metric.set(value)
                                
                        self.logger.verbose(f"Metric update completed successfully with storage key: {storage_key}")

                    except Exception as e:
                        self.logger.error(
                            f"Failed to update metric value:\n"
                            f"- Base key: {key}\n"
                            f"- Storage key: {storage_key}\n"
                            f"- Labels: {identifier.get_label_dict() if identifier.labels else 'none'}\n"
                            f"- Value: {value}\n"
                            f"- Error: {e}",
                            exc_info=True
                        )
                    else:
                        self.logger.verbose(
                            f"Successfully updated metric:\n"
                            f"- Base key: {key}\n"
                            f"- Storage key: {storage_key}\n"
                            f"- Labels: {identifier.get_label_dict() if identifier.labels else 'none'}\n"
                            f"- Value: {value}"
                        )
                else:
                    self.logger.warning(f"Skipping update for {storage_key} - value is None")
                        
            except Exception as e:
                self.logger.error(
                    f"Failed to process metric:\n"
                    f"- Key: {key}\n"
                    f"- Error: {e}",
                    exc_info=True
                )

        # Log final storage state for debugging
        self.logger.verbose("Final storage state:")
        for storage_key in sorted(self._prometheus_metrics.keys()):
            self.logger.verbose(f"  - {storage_key}")

    def _update_internal_metrics(self, successes: int, errors: int, duration: float):
        """Update internal metrics."""
        collection_time = round(self.config.now_utc().timestamp(), 3)

        self._internal_metrics['collection_successful'].set(self.stats.successful)
        self._internal_metrics['collection_errors'].set(self.stats.errors)
        self._internal_metrics['collection_duration'].set(duration)
        self._internal_metrics['uptime'].set(self.config.get_uptime_seconds())
        self._internal_metrics['last_collection_unix_seconds'].set(collection_time)

    async def collect_all_metrics(self) -> bool:
        """Collect metrics from all services with parallel execution."""
        collection_start = self.config.now_utc().timestamp()
        self.stats.attempts += 1
        success_count = 0
        errors = 0
        
        try:
            # Debug log the collection attempt
            self.logger.debug(f"Starting metrics collection with {len(self.service_collectors)} collectors")
            
            # Update uptime metric
            self._internal_metrics['uptime'].set(self.config.get_uptime_seconds())
            
            # Collect from all services in parallel
            service_results = await self.collection_manager.collect_services(
                self.service_collectors
            )
            
            # Process results from each service into a single update batch
            metrics_to_update = {}
            for service_name, metrics in service_results.items():
                self.logger.verbose(f"Processing results for service {service_name}")
                if isinstance(metrics, Dict) and metrics:  # Added explicit empty dict check
                    # Track success/failure for each individual metric
                    for metric_key, metric_result in metrics.items():
                        try:
                            if not isinstance(metric_result, tuple) or len(metric_result) != 2:  # Added type validation
                                self.logger.error(f"Invalid metric result format for {metric_key}: {metric_result}")
                                errors += 1
                                continue
                                
                            identifier, value = metric_result
                            # Add detailed label logging
                            self.logger.verbose(f"\nProcessing metric result:"
                                            f"\nKey: {metric_key}"
                                            f"\nIdentifier: {identifier.get_debug_info()}"
                                            f"\nValue: {value}"
                                            f"\nLabel count: {len(identifier.labels)}")
                            if identifier.labels:
                                self.logger.verbose("Labels:")
                                for label in identifier.labels:
                                    self.logger.verbose(f"  - {label.name}: {label.value}")
                                    
                            if value is None:
                                self.logger.error(f"Null value for metric {metric_key}")
                                errors += 1
                                continue
                                
                            metrics_to_update[metric_key] = metric_result
                            success_count += 1
                            
                        except Exception as e:
                            self.logger.error(f"Failed to process metric {metric_key}: {e}")
                            errors += 1
                else:
                    self.logger.error(f"Failed to collect metrics for {service_name}: empty or invalid result")
                    errors += 1
            
            # Update all metrics in a single batch
            if metrics_to_update:
                self.logger.verbose(f"Updating {len(metrics_to_update)} metrics in batch")
                # Add summary of labels being passed
                self.logger.verbose("Metrics being passed to update:")
                for key, (identifier, _) in metrics_to_update.items():
                    self.logger.verbose(f"{key}: {len(identifier.labels)} labels")
                self._update_prometheus_metrics(metrics_to_update)
            
            # Debug log final metrics state
            self.logger.debug(f"Current metrics count: {len(self._prometheus_metrics)}")
            
            # Update statistics
            collection_time = self.config.now_utc().timestamp() - collection_start
            self.stats.successful += success_count
            self.stats.errors += errors
            
            if success_count == 0:
                self.stats.consecutive_failures += 1
            else:
                self.stats.consecutive_failures = 0
            
            self.stats.update_collection_time(collection_start)
            
            # Update internal metrics
            self._update_internal_metrics(success_count, errors, collection_time)
            
            success_rate = 0.0
            total_metrics = success_count + errors
            if total_metrics > 0:
                success_rate = (success_count / total_metrics) * 100
            
            self.logger.info(
                f"Metrics collection completed in {collection_time:.2f}s: "
                f"{success_count} successful, {errors} errors "
                f"({success_rate:.1f}% success rate)"
            )
            
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}", exc_info=True)
            return False
    
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Health Check Endpoint
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class HealthCheck:
    """Health check endpoint implementation.
    
    Provides HTTP endpoint for monitoring service health and getting
    operational metrics. Implements a REST API with JSON responses.
    
    Endpoints:
        GET /health: Service health status
        GET /health?include_metrics=true: Status with metrics inventory
    
    Response Format:
        {
            "service": {
                "status": "healthy|unhealthy",
                "up": true,
                ...
            },
            "stats": {
                "collection": {...},
                "configuration": {...}
            },
            "files": {...},
            "metrics": {...}  # If requested
        }
    """

    def __init__(
        self, 
        config: ProgramConfig,
        metrics_collector: MetricsCollector,
        logger: logging.Logger
    ):
        self.config = config
        self.metrics_collector = metrics_collector
        self.logger = logger
        self._server = None
        self._thread = None

    def start(self) -> bool:
        """Start health check server in a separate thread."""
        try:
            app = self._create_wsgi_app()
            self._server = make_server('', self.config.health_port, app)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="HealthCheckServer",
                daemon=True
            )
            self._thread.start()
            self.logger.info(f"Started health check server on port {self.config.health_port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start health check server: {e}")
            return False

    def stop(self) -> None:
        """Stop health check server."""

        if not self._server:
            return

        try:
            self.logger.info("Stopping health check server")
            self._server.shutdown()
            self._server.server_close()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=5)
                if self._thread.is_alive():
                    self.logger.warning("Health check server thread failed to stop")
        except Exception as e:
            self.logger.error(f"Error stopping health check server: {e}")
        finally:
            self._server = None
            self._thread = None

    def _create_error_response(self, status: str, message: str) -> bytes:
        """Create standardized error response."""
        response = {
            "status": status,
            "error": message,
            "timestamp_utc": self.config.now_utc().isoformat()
        }
        return json.dumps(response, indent=2).encode()

    def _create_wsgi_app(self):
        """Create WSGI application for health checks."""
        def app(environ, start_response):
            try:
                path = environ.get('PATH_INFO', '').rstrip('/')
                
                if path not in ['', '/health']:
                    start_response('404 Not Found', [('Content-Type', 'application/json')])
                    return [self._create_error_response("error", "Not Found")]

                is_healthy = self.metrics_collector.stats.is_healthy(
                    self.config.failure_threshold
                )
                
                status = '200 OK' if is_healthy else '503 Service Unavailable'
                headers = [
                    ('Content-Type', 'application/json'),
                    ('Cache-Control', 'no-cache, no-store, must-revalidate')
                ]
                start_response(status, headers)

                response = {
                    "service": {
                        "status": "healthy" if is_healthy else "unhealthy",
                        "up": True,
                        "current_datetime_utc": self.config.now_utc().isoformat(),
                        "service_start_datetime_utc": self.config._start_time.isoformat(),
                        "last_metrics_collection_datetime_utc": 
                            self.metrics_collector.stats.last_collection_datetime.isoformat(),
                        "uptime_seconds": round(self.config.get_uptime_seconds(), 6),
                        "process_id": os.getpid(),
                        "running_as": {
                            "user": self.config.exporter_user,
                            "uid": os.getuid(),
                            "gid": os.getgid()
                        },
                        "systemd_managed": self.config.running_under_systemd
                    },
                    "stats": {
                        "collection": {
                            "attempts": self.metrics_collector.stats.attempts,
                            "successful": self.metrics_collector.stats.successful,
                            "errors": self.metrics_collector.stats.errors,
                            "consecutive_failures": self.metrics_collector.stats.consecutive_failures,
                            "failure_threshold": self.config.failure_threshold,
                            "timing": {
                                "last_collection_seconds": round(
                                    self.metrics_collector.stats.last_collection_time, 3
                                ),
                                "average_collection_seconds": round(
                                    self.metrics_collector.stats.get_average_collection_time(), 3
                                )
                            }
                        },
                        "configuration": {
                            "poll_interval_seconds": self.config.poll_interval,
                            "max_workers": self.config.max_workers,
                            "collection_timeout_seconds": self.config.collection_timeout
                        }
                    },
                    "files": {
                        "script": {
                            "name": self.config._source.base_name,
                            "path": str(self.config._source.script_path.resolve()),
                            "directory": str(self.config._source.script_dir)
                        },
                        "config": {
                            "path": str(self.config._source.config_path),
                            "last_modified_utc": datetime.fromtimestamp(
                                self.config._source.config_path.stat().st_mtime, 
                                tz=timezone.utc
                            ).isoformat()
                        },
                        "log": {
                            "path": str(self.config._source.log_path),
                            "level": self.config.logging.get('level', 'DEBUG'),
                            "file_level": self.config.logging.get('file_level', 'DEBUG'),
                            "console_level": self.config.logging.get('console_level', 'INFO'),
                            "journal_level": self.config.logging.get('journal_level', 'WARNING'),
                            "max_size_bytes": self.config.logging.get('max_bytes', 10485760),
                            "backup_count": self.config.logging.get('backup_count', 3)
                        },
                        "sudoers": {
                            "path": str(self.config._source.sudoers_path),
                            "file": self.config._source.sudoers_file
                        }
                    }
                }

                # Add metrics inventory if requested
                if environ.get('QUERY_STRING') == 'include_metrics=true':
                    self.logger.verbose("Generating metrics inventory...")
                    metrics = self._get_metrics_inventory()
                    self.logger.verbose(f"Generated inventory: {json.dumps(metrics, indent=2)}")
                    response["metrics"] = metrics
                
                return [json.dumps(response, indent=2).encode()]
        
            except Exception as e:
                self.logger.error(f"Health check error: {e}", exc_info=True)
                start_response('500 Internal Server Error', [('Content-Type', 'application/json')])
                return [self._create_error_response("error", str(e))]

        return app
    
    def _get_metrics_inventory(self) -> Dict[str, Any]:
        """Get metrics inventory with collection status."""
        metrics_info = OrderedDict()
        services_config = self.config.services
        
        for service_name in sorted(services_config.keys()):
            service_config = services_config[service_name]
            service_info = {
                "description": service_config.get("description", ""),
                "run_as": service_config.get("run_as"),
                "metric_groups": OrderedDict()
            }
            
            for group_name in sorted(service_config.get("metric_groups", {}).keys()):
                group_config = service_config["metric_groups"][group_name]
                group_type = MetricGroupType.from_config(group_config)
                
                group_info = {
                    "type": group_type.value,
                    "command": group_config.get("command", "") if group_type == MetricGroupType.DYNAMIC else None,
                    "labels": group_config.get("labels", {}),  # Add group-level labels
                    "metrics": OrderedDict()
                }
                
                for metric_name, metric_config in sorted(group_config.get("metrics", {}).items()):
                    metric_info = OrderedDict([
                        ("type", metric_config.get("type", "static")),
                        ("description", metric_config.get("description", "")),
                        ("prometheus_name", f"{service_name}_{group_name}_{metric_name}"),
                        ("settings", OrderedDict([
                            ("content_type", metric_config.get("content_type", "text")),
                            ("filter", metric_config.get("filter", "")),
                            ("transform", metric_config.get("transform", "")),
                            ("labels", metric_config.get("labels", {}))  # Add metric-level labels
                        ]))
                    ])
                    group_info["metrics"][metric_name] = metric_info
                
                if group_info["metrics"]:
                    service_info["metric_groups"][group_name] = group_info
                    
            if service_info["metric_groups"]:
                metrics_info[service_name] = service_info

        return metrics_info

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Main Service Class and Entry Point
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricsExporter:
    """Main service class for Prometheus metrics exporter.
    
    This class manages the lifecycle of the metrics collection service,
    including server startup/shutdown, metric collection, and health checks.
    
    Attributes:
        source (ProgramSource): Program source information
        config (ProgramConfig): Program configuration
        logger (logging.Logger): Configured logger instance
        shutdown_event (threading.Event): Event for coordinating shutdown
        _servers_started (bool): Track if servers are running
        user_manager (Optional[ServiceUserManager]): User permission manager
        metrics_collector (MetricsCollector): Metrics collection manager
        health_check (HealthCheck): Health check endpoint handler
    
    Raises:
        RuntimeError: If required users are missing or sudo setup fails
        OSError: If required ports are unavailable
        Exception: For other initialization failures
    """

    SHUTDOWN_TIMEOUT = 30  # seconds

    def __init__(
        self,
        source: ProgramSource,
        config: ProgramConfig,
        logger: logging.Logger
    ):
        """Initialize the metrics exporter service.
        
        Args:
            source: Program source information
            config: Program configuration
            logger: Configured logger instance
        """
        self.source = source
        self.config = config
        self.logger = logger
        self.shutdown_event = asyncio.Event()
        self.shutdown_complete = asyncio.Event()
        self._servers_started = False
        
        self.logger.info("Starting metrics exporter initialization")
        
        # Initialize user management
        if os.geteuid() == 0:
            try:
                self.user_manager = ServiceUserManager(self.config, self.logger)
                self.user_manager.collect_service_users()
                if not self.user_manager.ensure_users_exist():
                    raise RuntimeError("Missing required system users")
                if not self.user_manager.update_sudo_permissions():
                    raise RuntimeError("Failed to update sudo permissions")
            except Exception as e:
                self.logger.error(f"Failed to initialize user management: {e}")
                raise
        else:
            self.logger.warning("Not running as root, skipping user management")
            self.user_manager = None
        
        # Initialize metrics collection
        self.metrics_collector = MetricsCollector(self.config, self.logger)
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        # Initialize health check endpoint
        self.health_check = HealthCheck(self.config, self.metrics_collector, self.logger)

        self.logger.info("Metrics exporter initialized")

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"Received {signal_name}, initiating shutdown...")
        try:
            self.logger.verbose("Cleanup completed, setting shutdown event")
            asyncio.get_event_loop().call_soon_threadsafe(self.shutdown_event.set)
        except Exception as e:
            self.logger.error(f"Error during signal cleanup: {e}")

    def check_ports(self) -> bool:
        """Check if required ports are available."""
        port_configs = [
            (self.config.metrics_port, "metrics"),
            (self.config.health_port, "health check")
        ]
        
        for port, name in port_configs:
            if not self._check_port_available(port, name):
                return False
        return True

    def _check_port_available(self, port: int, name: str) -> bool:
        """Check if a specific port is available."""
        if port < 1 or port > 65535:
            self.logger.error(f"Invalid {name} port {port}: must be between 1-65535")
            return False
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('', port))
            sock.close()
            return True
        except OSError as e:
            self.logger.error(f"{name.title()} port {port} is not available: {e}")
            return False

    def _start_servers(self) -> bool:
        """Start metrics and health check servers."""
        try:
            # Always start metrics server first
            try:
                start_http_server(self.config.metrics_port)
                self.logger.info(f"Started metrics server on port {self.config.metrics_port}")
            except Exception as e:
                self.logger.error(f"Failed to start metrics server: {e}")
                return False

            # Only start health check if metrics succeeded
            try:
                if not self.health_check.start():
                    self.logger.error("Failed to start health check server")
                    self.logger.info("Stopping metrics server (via process termination)")
                    return False
                self.logger.info(f"Started health check server on port {self.config.health_port}")
            except Exception as e:
                self.logger.error(f"Failed to start health check server: {e}")
                self.logger.info("Stopping metrics server (via process termination)")
                return False

            self._servers_started = True
            return True

        except Exception as e:
            self.logger.error(f"Unexpected error starting servers: {e}")
            return False

    async def _cleanup_async(self):
        """Asynchronous cleanup of resources with proper resource cleanup."""
        if not self._servers_started:
            return
        
        try:
            # 1. Stop accepting new metrics collections
            self.logger.info("Stopping metric collections...")
            if hasattr(self.metrics_collector, '_semaphore'):
                # Prevent new collections from starting
                self.metrics_collector._semaphore._value = 0
                
            # 2. Allow pending collections to finish (with timeout matching poll interval)
            try:
                pending = [task for task in asyncio.all_tasks() 
                        if not task.done() and task != asyncio.current_task()]
                if pending:
                    self.logger.info(f"Waiting for {len(pending)} pending tasks...")
                    await asyncio.wait(pending, timeout=self.config.poll_interval)
            except asyncio.TimeoutError:
                self.logger.warning("Some tasks did not complete in time")

            # 3. Stop health check server (which has its own thread)
            if self.health_check:
                self.logger.info("Stopping health check server...")
                self.health_check.stop()
                
            # 4. Close log handlers explicitly
            self.logger.info("Closing log handlers...")
            for handler in self.logger.handlers:
                try:
                    handler.close()
                except Exception as e:
                    self.logger.error(f"Error closing log handler: {e}")

            # 5. Notify systemd before final cleanup
            if self.config.running_under_systemd:
                notify(Notification.STOPPING)
                
            # 6. Final cleanup
            # prometheus_client server will stop with process
            self.logger.info("Metrics server will stop with process termination")

        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
        finally:
            self._servers_started = False
            self.shutdown_complete.set()

    async def run(self):
        """Main service loop."""
        try:

            # Create a simple test metric
            # test_metric = Gauge('test_metric', 'Test metric to verify Prometheus registration')
            # test_metric.set(42.0)

            # Check ports before starting
            if not self.check_ports():
                self.logger.error("Required ports are not available")
                if self.config.running_under_systemd:
                    notify(Notification.STOPPING)
                return 1

            # Start servers
            if not self._start_servers():
                if self.config.running_under_systemd:
                    notify(Notification.STOPPING)
                return 1

            # Notify systemd we're ready
            if self.config.running_under_systemd:
                notify(Notification.READY)
            
            # Main collection loop with shutdown timeout
            try:
                while not self.shutdown_event.is_set():
                    try:
                        loop_start = self.config.now_utc().timestamp()
                        await self.metrics_collector.collect_all_metrics()
                        
                        elapsed = self.config.now_utc().timestamp() - loop_start
                        sleep_time = max(0, self.config.poll_interval - elapsed)
                        
                        if sleep_time > 0:
                            try:
                                # Wait for shutdown event or timeout
                                await asyncio.wait_for(self.shutdown_event.wait(), timeout=sleep_time)
                            except asyncio.TimeoutError:
                                continue  # Normal timeout, continue collection
                        else:
                            self.logger.warning(
                                f"Collection took longer than poll interval "
                                f"({elapsed:.2f}s > {self.config.poll_interval}s)"
                            )
                        
                    except Exception as e:
                        self.logger.error(f"Error in main loop: {e}")
                        self.logger.verbose("Exception details:", exc_info=True)
                        await asyncio.sleep(1)  # Avoid tight loop on persistent errors
            
                self.logger.info("Shutdown event received, stopping service")

                # Start cleanup and wait with timeout
                cleanup_task = asyncio.create_task(self._cleanup_async())
                try:
                    await asyncio.wait_for(self.shutdown_complete.wait(), timeout=self.SHUTDOWN_TIMEOUT)
                    self.logger.info("Cleanup completed successfully")
                except asyncio.TimeoutError:
                    self.logger.error(f"Cleanup timed out after {self.SHUTDOWN_TIMEOUT} seconds")
                    if self.config.running_under_systemd:
                        notify(Notification.STOPPING)
                    return 1

            except asyncio.CancelledError:
                self.logger.warning("Service operation cancelled")
                raise

            return 0
            
        except Exception as e:
            self.logger.exception(f"Fatal error in service: {e}")
            return 1

        finally:
            # Final cleanup attempt if timeout occurred
            if not self.shutdown_complete.is_set():
                self.logger.warning("Forcing final cleanup")
                try:
                    await self._cleanup_async()
                except Exception as e:
                    self.logger.error(f"Error during final cleanup: {e}")
            
            if self.config.running_under_systemd:
                notify(Notification.STOPPING)
            self.logger.info("Service shutdown complete")

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

async def main():
    """Entry point for the metrics exporter service."""
    exporter = None
    try:
        source = ProgramSource()
        config = ProgramConfig(source)
        program_logger = ProgramLogger(source, config)
        logger = program_logger.logger
        config.initialize()

        try:
            exporter = MetricsExporter(source, config, logger)
            return await exporter.run()
        
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            if exporter:
                # Call cleanup method before exiting
                await exporter._cleanup_async()
                if exporter.config.running_under_systemd:
                    notify(Notification.STOPPING)
            return 0
        
    except Exception as e:
        print(f"Fatal error during startup: {e}", file=sys.stderr)
        if exporter:
            await exporter._cleanup_async()
        return 1

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
    
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~