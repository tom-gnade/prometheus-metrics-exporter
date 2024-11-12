#!/etc/prometheus/exporter/venv/bin/python3 -u

"""
Prometheus Metrics Exporter

Description:
---------------------

A flexible metrics collection and exposition service supporting:
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

Note: in VS Code, use CTRL+K, CTRL+0 tol collapse all, CTRL+K, CTRL+J to expand all code segments
"""

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Imports
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

# Standard library imports
import asyncio
import json
import logging
import os
import pwd
import grp
import re
import signal
import socket
import sys
import threading
import time
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Awaitable, Any, Dict, List, Optional, Union
from functools import wraps

# Third party imports
from prometheus_client import start_http_server, Gauge, make_wsgi_app
from wsgiref.simple_server import make_server
from cysystemd.daemon import notify, Notification
from cysystemd import journal
import yaml
import requests

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

class MetricType(Enum):
    """Types of metrics supported."""
    GAUGE = "gauge"    # A value that can go up and down (default)
    STATIC = "static"  # Fixed value that rarely changes

class ContentType(Enum):
    """Content types for data sources."""
    TEXT = "text"
    JSON = "json"
    PROMETHEUS = "prometheus"
    
    def parse_value(self, content: str, filter_expr: str) -> Optional[float]:
        """Parse content based on content type."""
        try:
            if self == ContentType.TEXT:
                match = re.search(filter_expr, content)
                return float(match.group(1)) if match else None
                
            elif self == ContentType.JSON:
                data = json.loads(content)
                for key in filter_expr.strip('.').split('.'):
                    data = data[key]
                return float(data)
                
            elif self == ContentType.PROMETHEUS:
                for line in content.splitlines():
                    if line.startswith(filter_expr):
                        return float(line.split()[-1])
                return None
                
            return None
            
        except Exception as e:
            logging.warning(f"Failed to parse {self.value} response: {e}")
            return None

@dataclass
class CollectionResult:
    """Result of metric collection attempt."""
    success: bool
    value: Optional[float] = None
    error: Optional[str] = None

@dataclass
class CollectionStats:
    """Statistics for metric collection operations."""
    attempts: int = 0
    successful: int = 0
    warnings: int = 0
    errors: int = 0
    consecutive_failures: int = 0
    last_collection_time: float = 0
    total_collection_time: float = 0
    
    def reset(self):
        """Reset all statistics to initial values."""
        self.attempts = 0
        self.successful = 0
        self.warnings = 0
        self.errors = 0
        self.consecutive_failures = 0
        self.last_collection_time = 0
        self.total_collection_time = 0
    
    def update_collection_time(self, start_time: float):
        """Update collection timing statistics."""
        collection_time = time.time() - start_time
        self.last_collection_time = collection_time
        self.total_collection_time += collection_time
    
    def get_average_collection_time(self) -> float:
        """Calculate average collection time."""
        return self.total_collection_time / self.attempts if self.attempts > 0 else 0
    
    def is_healthy(self, threshold: int) -> bool:
        """Determine if collection statistics indicate healthy operation."""
        return self.consecutive_failures < threshold

@dataclass
class CommandResult:
    """Result of a command execution."""
    output: Optional[str]
    success: bool
    error_message: Optional[str] = None
    execution_time: float = 0
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class MetricTemplate:
    """Template for metric collection configuration."""
    collection_frequency: int = 0
    content_type: ContentType = ContentType.TEXT

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# User Management
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ServiceUserManager:
    """Manages service users and sudo permissions."""

    SUDOERS_DIR = "/etc/sudoers.d"
    SUDOERS_FILE = "prometheus-metrics-exporter"

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.service_users: set[str] = set()
        self.exporter_user = "prometheus"
        self.allowed_commands = {
            'du': '/usr/bin/du',
            'goal': '/usr/bin/goal',
            'systemctl': '/usr/bin/systemctl',
            'cat': '/bin/cat'
        }

    def collect_service_users(self) -> set[str]:
        """Collect all unique service users from configuration."""
        users = {self.exporter_user}
        
        for service_config in self.config.get('services', {}).values():
            if 'run_as' in service_config:
                user = service_config['run_as'].get('user')
                if user:
                    users.add(user)
        
        self.service_users = users
        return users

    def generate_sudoers_content(self) -> str:
        """Generate sudoers file content for all service users."""
        content = [
            "# Auto-generated by Prometheus Metrics Exporter",
            "# Do not edit manually - changes will be overwritten",
            ""
        ]

        for user in sorted(self.service_users - {self.exporter_user}):
            for cmd_name, cmd_path in sorted(self.allowed_commands.items()):
                content.append(f"{self.exporter_user} ALL=({user}) NOPASSWD: {cmd_path}")

        return "\n".join(content) + "\n"

    def update_sudo_permissions(self) -> bool:
        """Update sudoers configuration for service users."""
        try:
            if os.geteuid() != 0:
                self.logger.error("Must be root to update sudo permissions")
                return False

            sudoers_path = os.path.join(self.SUDOERS_DIR, self.SUDOERS_FILE)
            
            content = self.generate_sudoers_content()
            
            temp_path = f"{sudoers_path}.tmp"
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

class UserContext:
    """Manages user context for command execution."""
    
    def __init__(self, run_as_config: Dict[str, Any], logger: logging.Logger):
        self.config = run_as_config
        self.logger = logger
        self._original_uid = os.getuid()
        self._original_gid = os.getgid()
        self._enabled = self._original_uid == 0
        
        self.username = run_as_config['user']
        self.groupname = run_as_config.get('group', self.username)
        
        try:
            self.user_info = pwd.getpwnam(self.username)
            self.group_info = grp.getgrnam(self.groupname)
        except KeyError as e:
            self.logger.error(f"Invalid user or group: {e}")
            self._enabled = False
    
    @contextmanager
    def temp_context(self):
        """Temporarily switch user context if running as root."""
        if not self._enabled:
            self.logger.warning(
                f"User switching disabled (not running as root). "
                f"Commands will run as current user."
            )
            yield
            return

        try:
            self.logger.debug(f"Switching to user {self.username} (uid={self.user_info.pw_uid})")
            
            os.setegid(self.group_info.gr_gid)
            os.seteuid(self.user_info.pw_uid)
            
            try:
                yield
            finally:
                os.seteuid(self._original_uid)
                os.setegid(self._original_gid)
                self.logger.debug(f"Restored original user (uid={self._original_uid})")
                
        except Exception as e:
            self.logger.error(
                f"Failed to switch to user {self.username}: {e}"
            )
            raise
        
        #-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Command Execution
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class CommandExecutor:
    """Executes commands with user context support."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    async def execute_command(
        self,
        command: str,
        user_context: Optional[UserContext] = None
    ) -> CommandResult:
        """Execute command with optional user context."""
        self.logger.debug(f"Executing command: {command}")
        start_time = time.time()
        
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
                execution_time=time.time() - start_time
            )
    
    async def _execute(self, command: str) -> CommandResult:
        """Execute shell command."""
        start_time = time.time()
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            execution_time = time.time() - start_time
            
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
                execution_time=time.time() - start_time
            )

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Metrics Collection
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ParallelCollectionManager:
    """Manages parallel collection at service and group levels."""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.max_workers = config.get('exporter', {}).get('max_workers', 4)
        self.timeout = config.get('exporter', {}).get('collection_timeout_sec', 30)
        self._semaphore = asyncio.Semaphore(self.max_workers)
    
    async def collect_services(
        self,
        collectors: Dict[str, 'ServiceMetricsCollector']
    ) -> Dict[str, Dict[str, float]]:
        """Collect metrics from multiple services in parallel."""
        tasks = []
        service_names = []
        
        for service_name, collector in collectors.items():
            self.logger.debug(f"Creating collection task for service: {service_name}")
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
                return await asyncio.wait_for(coro, timeout=self.timeout)
        except asyncio.TimeoutError:
            self.logger.error(f"Collection timed out for {identifier}")
            return None
        except Exception as e:
            self.logger.error(f"Collection failed for {identifier}: {e}")
            return None

class ServiceMetricsCollector:
    """Collects metrics for a specific service."""
    
    def __init__(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        logger: logging.Logger
    ):
        self.service_name = service_name
        self.service_config = service_config
        self.logger = logger
        self.metrics: Dict[str, Dict] = {}
        self.command_executor = CommandExecutor(logger)
        
        # Set up user context if specified
        self.user_context = None
        if 'run_as' in service_config:
            try:
                self.user_context = UserContext(service_config['run_as'], logger)
            except Exception as e:
                self.logger.error(f"Failed to initialize user context for {service_name}: {e}")
    
    async def collect_metrics(self) -> Dict[str, float]:
        """Collect all metrics for this service."""
        results = {}
        self.logger.debug(f"Starting metrics collection for service: {self.service_name}")
        
        for group_name, group_config in self.service_config.get('metric_groups', {}).items():
            self.logger.debug(f"Processing metric group: {group_name}")
            if not group_config.get('expose_metrics', True):
                self.logger.debug(f"Skipping unexposed group: {group_name}")
                continue
            
            try:
                self.logger.debug(f"Collecting metrics for group: {group_name}")
                group_metrics = await self.collect_group(group_name, group_config)
                self.logger.debug(f"Group {group_name} collection results: {group_metrics}")
                results.update(group_metrics)
            except Exception as e:
                self.logger.error(f"Failed to collect metric group {group_name}: {e}")
        
        self.logger.debug(f"Service {self.service_name} collection completed. Results: {results}")
        return results
    
    async def collect_group(
        self,
        group_name: str,
        group_config: Dict
    ) -> Dict[str, float]:
        """Collect all metrics in a group from a single source read."""
        self.logger.debug(f"Starting collection for group {group_name}")
        
        try:
            # Get the source data for the group
            command = group_config.get('command')
            if command:
                result = await self.command_executor.execute_command(
                    command,
                    self.user_context
                )
                source_data = result.output if result.success else None
                self.logger.debug(f"Command execution result: {result}")
            else:
                self.logger.error(f"No command specified for group {group_name}")
                return {}

            if source_data is None:
                self.logger.debug(f"No source data for group {group_name}")
                return {}
            
            results = {}
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                try:
                    # Construct full metric name from path components
                    full_metric_name = f"{self.service_name}_{group_name}_{metric_name}"
                    self.logger.debug(f"Processing metric: {full_metric_name}")
                    
                    # Get value based on metric type
                    value = self._parse_metric_value(source_data, metric_config)
                    
                    if value is not None:
                        results[full_metric_name] = value
                        self.metrics[metric_name] = {
                            'last_value': value,
                            'last_collection': time.time()
                        }
                except Exception as e:
                    self.logger.error(f"Failed to parse metric {metric_name}: {e}")
                    
            return results
                
        except Exception as e:
            self.logger.error(f"Failed to collect group {group_name}: {e}")
            return {}
    
    def _parse_metric_value(
        self,
        source_data: str,
        metric_config: Dict
    ) -> Optional[float]:
        """Parse individual metric value from group's source data."""
        try:
            # Handle static metrics
            if metric_config.get('type') == 'static':
                self.logger.debug("Processing static metric with value: %s", 
                                metric_config.get('value'))
                return float(metric_config['value'])

            # Handle gauge metrics (default)
            content_type = metric_config.get('content_type', 'text')
            content_type_enum = ContentType(content_type)
            value = content_type_enum.parse_value(
                source_data,
                metric_config['filter']
            )
            
            if value is None and 'value_on_error' in metric_config:
                return metric_config['value_on_error']

            return value

        except Exception as e:
            self.logger.error(f"Failed to parse value: {e}")
            if 'value_on_error' in metric_config:
                return metric_config['value_on_error']
            return None

    def _should_collect_group(self, group_config: Dict) -> bool:
        """Determine if group should be collected based on frequency."""
        frequency = group_config.get('collection_frequency', 0)
        if frequency == 0:
            return True

        last_collection = min(
            self.metrics.get(metric_name, {}).get('last_collection', 0)
            for metric_name in group_config.get('metrics', {})
        )

        return (time.time() - last_collection) >= frequency

    def _get_cached_group_metrics(self, group_name: str) -> Dict[str, float]:
        """Get cached metrics for a group."""
        results = {}
        group_config = self.service_config['metric_groups'][group_name]
        
        for metric_name in group_config.get('metrics', {}):
            if metric_name in self.metrics:
                full_metric_name = f"{self.service_name}_{group_name}_{metric_name}"
                results[full_metric_name] = self.metrics[metric_name]['last_value']
        
        return results


class MetricsCollector:
    """Main metrics collector managing multiple services."""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.stats = CollectionStats()
        self.service_collectors: Dict[str, ServiceMetricsCollector] = {}
        self._prometheus_metrics: Dict[str, Gauge] = {}
        self.start_time = datetime.now()
        self.parallel_manager = ParallelCollectionManager(config, logger)
        
        # Initialize collectors for each service
        self._initialize_collectors()
        
        # Set up internal metrics
        self._setup_internal_metrics()
    
    def _initialize_collectors(self):
        """Initialize collectors for each service."""
        services = self.config.get('services', {})
        for service_name, service_config in services.items():
            try:
                self.service_collectors[service_name] = ServiceMetricsCollector(
                    service_name,
                    service_config,
                    self.logger
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
            )
        }

    def get_uptime(self) -> float:
        """Get service uptime in seconds."""
        return (datetime.now() - self.start_time).total_seconds()

    async def collect_all_metrics(self) -> bool:
        """Collect metrics from all services with parallel execution."""
        collection_start = time.time()
        self.stats.attempts += 1
        success_count = 0
        errors = 0
        
        try:
            # Update uptime metric
            self._internal_metrics['uptime'].set(self.get_uptime())
            
            # Collect from all services in parallel
            service_results = await self.parallel_manager.collect_services(
                self.service_collectors
            )
            
            # Process results from each service
            for service_name, metrics in service_results.items():
                if isinstance(metrics, Dict):
                    success_count += len(metrics)
                    self._update_prometheus_metrics(metrics)
                else:
                    self.logger.error(
                        f"Failed to collect metrics for {service_name}"
                    )
                    errors += 1
            
            # Update statistics
            collection_time = time.time() - collection_start
            self.stats.successful += success_count
            self.stats.errors += errors
            
            if errors == len(self.service_collectors):
                self.stats.consecutive_failures += 1
            else:
                self.stats.consecutive_failures = 0
            
            self.stats.update_collection_time(collection_start)
            
            # Update internal metrics
            self._update_internal_metrics(success_count, errors, collection_time)
            
            success_rate = (
                (success_count / (success_count + errors) * 100)
                if (success_count + errors) > 0 else 0
            )
            
            self.logger.info(
                f"Metrics collection completed in {collection_time:.2f}s: "
                f"{success_count} successful, {errors} errors "
                f"({success_rate:.1f}% success rate)"
            )
            
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return False
    
    def _update_prometheus_metrics(self, metrics: Dict[str, float]):
        """Update Prometheus metrics with collected values."""
        for metric_name, value in metrics.items():
            if metric_name not in self._prometheus_metrics:
                self._prometheus_metrics[metric_name] = Gauge(
                    metric_name,
                    self._get_metric_description(metric_name)
                )
            if value is not None:
                self._prometheus_metrics[metric_name].set(value)
    
    def _update_internal_metrics(self, successes: int, errors: int, duration: float):
        """Update internal metrics."""
        self._internal_metrics['collection_successful'].set(self.stats.successful)
        self._internal_metrics['collection_errors'].set(self.stats.errors)
        self._internal_metrics['collection_duration'].set(duration)
        self._internal_metrics['uptime'].set(self.get_uptime())
    
    def _get_metric_description(self, metric_name: str) -> str:
        """Get description for a metric from configuration."""
        for collector in self.service_collectors.values():
            for group in collector.service_config.get('metric_groups', {}).values():
                for metric in group.get('metrics', {}).values():
                    if f"{collector.service_name}_{metric_name}" == metric_name:
                        return metric.get('description', f"Metric {metric_name}")
        return f"Metric {metric_name}"

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Main Service Class and Entry Point
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricsExporter:
    """Main service class for Prometheus metrics exporter."""
    
    def __init__(self):
        print("Starting MetricsExporter initialization")
        self.running_under_systemd = bool(os.getenv('INVOCATION_ID'))
        print(f"Running under systemd: {self.running_under_systemd}")
        self.shutdown_event = threading.Event()
        
        # Set up logging first
        self.logger = self._setup_logging()
        
        # Load configuration
        try:
            self.config = self._load_config()
            print(f"DEBUG: Initial config load: {self.config}")
            print(f"DEBUG: Logging config: {self.config.get('logging', {})}")
            
            # Reinitialize logging with config
            if 'logging' in self.config:
                self.logger = self._setup_logging(self.config['logging'])
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise
        
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
        
        self.logger.info("Metrics exporter initialized")

    def _setup_logging(self, config: Dict = None) -> logging.Logger:
        """Set up logging with optional configuration."""
        logger = logging.getLogger(os.path.splitext(os.path.basename(sys.argv[0]))[0])
        logger.handlers.clear()
        log_level = logging.DEBUG
        logger.setLevel(log_level)
        
        max_bytes = 10 * 1024 * 1024  # 10MB
        backup_count = 3

        # Get defaults or configured values
        if config:
            log_level_override = config.get('level', log_level)
            max_bytes = config.get('max_bytes', max_bytes)
            backup_count = config.get('backup_count', backup_count)

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s [%(process)d] [%(threadName)s] '
            '[%(name)s.%(funcName)s] [%(levelname)s] %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
        
        # File handler - always DEBUG
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        log_file = os.path.join(script_dir, os.path.splitext(os.path.basename(sys.argv[0]))[0] + '.log')

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG) # May revert to log_level_override to trim log file output
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console handler - INFO
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level_override) # May revert to logging.INFO later
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # Journal handler - WARNING when under systemd
        if self.running_under_systemd:
            journal_handler = journal.JournaldLogHandler()
            journal_handler.setLevel(logging.WARNING) # Only display WARNING or ERROR to systemd/journald
            journal_handler.setFormatter(formatter)
            logger.addHandler(journal_handler)
        
        return logger

    def _load_config(self) -> Dict[str, Any]:
        """Load and validate configuration."""
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(sys.argv[0])),
            os.path.splitext(os.path.basename(sys.argv[0]))[0] + '.yml'
        )
        self.logger.debug(f"Loading config from: {config_path}")
        
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
                self.logger.debug(f"Loaded config: {config}")
                
            if not config:
                raise MetricConfigurationError("Empty configuration file")
                
            required_sections = ['exporter', 'services']
            for section in required_sections:
                if section not in config:
                    raise MetricConfigurationError(f"Missing required section: {section}")
            
            return config
            
        except Exception as e:
            raise MetricConfigurationError(f"Failed to load config: {e}")

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"Received {signal_name}, initiating shutdown...")
        if self.running_under_systemd:
            notify(Notification.STOPPING)
        self.shutdown_event.set()

    def check_ports(self) -> bool:
        """Check if required ports are available."""
        ports = [
            self.config['exporter']['metrics_port']
        ]
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('', port))
                sock.close()
            except OSError:
                self.logger.error(f"Port {port} is already in use")
                return False
        return True

    async def run(self):
        """Main service loop."""
        try:
            # Check ports before starting
            if not self.check_ports():
                self.logger.error("Required ports are not available")
                if self.running_under_systemd:
                    notify(Notification.STOPPING)
                return 1

            # Start Prometheus metrics server
            try:
                start_http_server(self.config['exporter']['metrics_port'])
                self.logger.info(
                    f"Started Prometheus metrics server on port "
                    f"{self.config['exporter']['metrics_port']}"
                )
            except Exception as e:
                self.logger.error(f"Failed to start metrics server: {e}")
                if self.running_under_systemd:
                    notify(Notification.STOPPING)
                return 1
            
            # Notify systemd we're ready
            if self.running_under_systemd:
                notify(Notification.READY)
            
            # Main collection loop
            while not self.shutdown_event.is_set():
                try:
                    loop_start = time.time()
                    
                    # Collect metrics
                    await self.metrics_collector.collect_all_metrics()
                    
                    # Calculate sleep time
                    elapsed = time.time() - loop_start
                    sleep_time = max(0, self.config['exporter']['poll_interval_sec'] - elapsed)
                    
                    if sleep_time > 0:
                        await asyncio.sleep(sleep_time)
                    else:
                        self.logger.warning(
                            f"Collection took longer than poll interval "
                            f"({elapsed:.2f}s > {self.config['exporter']['poll_interval_sec']}s)"
                        )
                    
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}")
                    self.logger.debug("Exception details:", exc_info=True)
                    await asyncio.sleep(1)  # Avoid tight loop on persistent errors
            
            self.logger.info("Shutdown event received, stopping service")
            return 0
            
        except Exception as e:
            self.logger.exception(f"Fatal error in service: {e}")
            if self.running_under_systemd:
                notify(Notification.STOPPING)
            return 1
            
        finally:
            self.logger.info("Service shutdown complete")

async def main():
    """Entry point for the metrics exporter service."""
    try:
        exporter = MetricsExporter()
        return await exporter.run()
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt, shutting down...")
        return 0
    except Exception as e:
        logging.error(f"Failed to start metrics exporter: {e}")
        return 1

if __name__ == '__main__':
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except Exception as e:
        logging.error(f"Fatal error in main: {e}")
        sys.exit(1)