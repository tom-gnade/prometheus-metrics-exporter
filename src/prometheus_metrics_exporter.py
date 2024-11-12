#!/etc/prometheus/exporters/venv/bin/python3

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
import aiohttp
import asyncio
import copy
import http.server
import json
import logging
import os
import pwd
import grp
import re
import signal
import socket
import stat
import subprocess
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
from typing import (
    Awaitable, Any, Callable, Dict, List, 
    Literal, Optional, Union, Set, Tuple, TypeVar
    )
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
# Core Enums
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricType(Enum):
    """Types of metrics and their collection methods."""
    STATIC = "static"    # Static values with optional labels
    COMMAND = "command"  # Shell command execution
    HTTP = "http"       # HTTP endpoint queries
    FILE = "file"      # File content monitoring

class ContentType(Enum):
    """Content types for data sources."""
    TEXT = "text"
    JSON = "json"
    PROMETHEUS = "prometheus"
    XML = "xml"
    
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
    labels: Dict[str, str] = field(default_factory=dict)

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Core Data Classes
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

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
class WatchedFile:
    """File tracking with caching."""
    path: str
    content_type: ContentType
    watch_type: Literal['config', 'log'] = 'config'
    last_modified: float = 0
    last_content: Optional[str] = None
    last_parsed_value: Optional[float] = None
    
    def needs_update(self) -> bool:
        """Check if file needs to be re-read."""
        try:
            return os.path.getmtime(self.path) > self.last_modified
        except Exception:
            return True
            
    def update(self, logger: logging.Logger) -> bool:
        """Update file content if changed."""
        try:
            if not self.needs_update():
                return False
                
            with open(self.path) as f:
                self.last_content = f.read()
                self.last_modified = os.path.getmtime(self.path)
                return True
        except Exception as e:
            logger.error(f"Failed to update watched file {self.path}: {e}")
            return False

@dataclass
class MetricDefinition:
    """Definition of a single metric."""
    name: str
    description: str
    type: str = "gauge"
    metric_type: MetricType = MetricType.HTTP
    content_type: ContentType = ContentType.TEXT
    filter: str = ""
    collection_frequency: int = 0
    source: Optional[str] = None
    endpoint: Optional[str] = None
    method: str = "GET"
    critical: bool = False
    last_collection: float = field(default_factory=time.time)
    last_value: Optional[float] = None
    template: Optional[str] = None
    
    def should_collect(self, current_time: float) -> bool:
        """Determine if metric should be collected based on frequency."""
        if self.metric_type == MetricType.STATIC:
            return self.last_value is None
            
        if self.collection_frequency == 0:
            return True
            
        return (current_time - self.last_collection) >= self.collection_frequency

@dataclass
class ServiceConfig:
    """Service configuration settings."""
    name: str
    description: Optional[str] = None
    metric_prefix: str = ""
    expose_metrics: bool = True
    ordinal: int = 999
    run_as: Optional[Dict[str, str]] = None
    metric_groups: Dict[str, Any] = field(default_factory=dict)
    templates: Dict[str, Any] = field(default_factory=dict)
    paths: Dict[str, str] = field(default_factory=dict)

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
        self.service_users: Set[str] = set()
        self.exporter_user = "prometheus"  # Default exporter user
        self.allowed_commands = {
            'du': '/usr/bin/du',
            'goal': '/usr/bin/goal',
            'systemctl': '/usr/bin/systemctl',
            'cat': '/bin/cat'
        }

    def collect_service_users(self) -> Set[str]:
        """Collect all unique service users from configuration."""
        users = {self.exporter_user}  # Always include exporter user
        
        for service_name, service_config in self.config.get('services', {}).items():
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

        # Allow the exporter user (prometheus) to run commands as other service users
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
            
            # Generate new content
            content = self.generate_sudoers_content()
            
            # Write to temporary file first
            temp_path = f"{sudoers_path}.tmp"
            with open(temp_path, 'w') as f:
                f.write(content)
            
            # Set correct permissions
            os.chmod(temp_path, 0o440)
            
            # Validate syntax
            result = subprocess.run(['visudo', '-c', '-f', temp_path], capture_output=True)
            if result.returncode != 0:
                self.logger.error(f"Invalid sudoers syntax: {result.stderr.decode()}")
                os.unlink(temp_path)
                return False
            
            # Move temporary file into place
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
        self._enabled = self._original_uid == 0  # Only enable if running as root
        
        # Get user and group info
        self.username = run_as_config['user']
        self.groupname = run_as_config.get('group', self.username)
        self.env = run_as_config.get('env', {})
        
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
            # Store original environment
            original_env = os.environ.copy()
            
            # Switch user/group
            os.setegid(self.group_info.gr_gid)
            os.seteuid(self.user_info.pw_uid)
            
            # Update environment
            if self.env:
                os.environ.update(self.env)
            
            # Set user environment variables
            os.environ['HOME'] = self.user_info.pw_dir
            os.environ['USER'] = self.username
            os.environ['LOGNAME'] = self.username
            
            try:
                yield
            finally:
                # Restore original user and environment
                os.seteuid(self._original_uid)
                os.setegid(self._original_gid)
                os.environ.clear()
                os.environ.update(original_env)
                
        except Exception as e:
            self.logger.error(
                f"Failed to switch to user {self.username} (running as uid={os.getuid()}): {e}"
            )
            raise
        
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Command Execution and File Watching
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class CommandExecutor:
    """Executes commands with user context support and caching."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._command_cache: Dict[str, Tuple[CommandResult, float]] = {}
        self._cache_timeout = 5.0  # 5 second cache timeout
    
    def _get_cached_result(self, command: str) -> Optional[CommandResult]:
        """Get cached command result if valid."""
        if command in self._command_cache:
            result, timestamp = self._command_cache[command]
            if time.time() - timestamp <= self._cache_timeout:
                return result
            del self._command_cache[command]
        return None
    
    async def execute_command(
        self,
        command: str,
        user_context: Optional[UserContext] = None,
        cache: bool = True
    ) -> CommandResult:
        """Execute command with optional user context and caching."""
        # Check cache first
        if cache:
            cached = self._get_cached_result(command)
            if cached:
                return cached

        start_time = time.time()
        try:
            if user_context:
                with user_context.temp_context():
                    result = await self._execute(command)
            else:
                result = await self._execute(command)
            
            # Cache successful results
            if cache and result.success:
                self._command_cache[command] = (result, time.time())
            
            return result
            
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

class FileWatcher:
    """Enhanced file watcher with type distinction."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.config_files: Dict[str, WatchedFile] = {}
        self.log_files: Dict[str, WatchedFile] = {}
        
    def add_file(self, path: str, content_type: ContentType, watch_type: str = 'config') -> None:
        """Add a file to watch."""
        try:
            watched = WatchedFile(path, content_type, watch_type)
            if watch_type == 'config':
                self.config_files[path] = watched
                self.logger.debug(f"Added config file to watch: {path}")
            elif watch_type == 'log':
                self.log_files[path] = watched
                self.logger.info(f"Added log file to watch: {path} (tailing not yet implemented)")
            else:
                raise ValueError(f"Unknown watch type: {watch_type}")
        except Exception as e:
            self.logger.error(f"Failed to add watched file {path}: {e}")
    
    def get_value(self, path: str, filter_expr: str) -> Optional[float]:
        """Get current value from watched file, updating if needed."""
        try:
            if path in self.config_files:
                watched = self.config_files[path]
            elif path in self.log_files:
                watched = self.log_files[path]
            else:
                self.logger.error(f"File not being watched: {path}")
                return None
                
            if watched.update(self.logger):
                # File changed, parse new value
                if watched.last_content is not None:
                    watched.last_parsed_value = watched.content_type.parse_value(
                        watched.last_content,
                        filter_expr
                    )
                    
            return watched.last_parsed_value
            
        except Exception as e:
            self.logger.error(f"Failed to get value from file {path}: {e}")
            return None

    def cleanup(self):
        """Clean up watched files."""
        self.config_files.clear()
        self.log_files.clear()

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
    
    async def collect_metric_groups(
        self,
        groups: Dict[str, Dict],
        collector: 'ServiceMetricsCollector'
    ) -> Dict[str, float]:
        """Collect metric groups in parallel within a service."""
        tasks = []
        group_names = []
        
        for group_name, group_config in groups.items():
            # Only create task if group has its own source
            if self._has_independent_source(group_config):
                tasks.append(
                    self.collect_with_timeout(
                        collector.collect_group(group_name, group_config),
                        f"{collector.service_name}.{group_name}"
                    )
                )
                group_names.append(group_name)
        
        if not tasks:
            return {}
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        metrics = {}
        for name, result in zip(group_names, results):
            if isinstance(result, dict):
                metrics.update(result)
            elif isinstance(result, Exception):
                collector.logger.error(f"Failed to collect group {name}: {result}")
        
        return metrics
    
    async def collect_with_timeout(
        self,
        coro: Awaitable,
        identifier: str
    ) -> Any:
        """Execute coroutine with timeout and semaphore."""
        try:
            async with self._semaphore:
                async with asyncio.timeout(self.timeout):
                    return await coro
        except asyncio.TimeoutError:
            self.logger.error(f"Collection timed out for {identifier}")
            return None
        except Exception as e:
            self.logger.error(f"Collection failed for {identifier}: {e}")
            return None
    
    def _has_independent_source(self, group_config: Dict) -> bool:
        """Determine if metric group has its own data source."""
        return (
            group_config.get('command') or
            group_config.get('source') or
            group_config.get('type') == 'static' or
            any(
                metric.get('type') == 'static'
                for metric in group_config.get('metrics', {}).values()
            )
        )

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
        self.file_watcher = FileWatcher(logger)
        
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
        
        for group_name, group_config in self.service_config.get('metric_groups', {}).items():
            if not group_config.get('expose_metrics', True):
                continue
            
            try:
                group_metrics = await self.collect_group(group_name, group_config)
                results.update(group_metrics)
            except Exception as e:
                self.logger.error(f"Failed to collect metric group {group_name}: {e}")
        
        return results
    
    async def collect_group(
        self,
        group_name: str,
        group_config: Dict
    ) -> Dict[str, float]:
        """Collect all metrics in a group from a single source read."""
        if not self._should_collect_group(group_config):
            return self._get_cached_group_metrics(group_name)
            
        try:
            # Get the source data once for the entire group
            source_data = await self._get_group_source_data(group_config)
            if source_data is None:
                return {}
            
            results = {}
            group_prefix = group_config.get('prefix', '')
            
            # Process all metrics using the single source data
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                try:
                    if metric_config.get('type') == 'static':
                        # Static metrics don't need source data
                        value = float(metric_config['value'])
                    else:
                        # Parse metric from the shared source data
                        value = self._parse_metric_value(source_data, metric_config)
                    
                    if value is not None:
                        full_metric_name = (
                            f"{self.service_config.get('metric_prefix', '')}"
                            f"{group_prefix}{metric_name}"
                        )
                        results[full_metric_name] = value
                        self.metrics[metric_name] = {
                            'last_value': value,
                            'last_collection': time.time()
                        }
                except Exception as e:
                    self.logger.error(f"Failed to parse metric {metric_name}: {e}")
                    if 'value_on_error' in metric_config:
                        results[full_metric_name] = metric_config['value_on_error']
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to collect metric group {group_name}: {e}")
            return {}
    
    async def _get_group_source_data(self, group_config: Dict) -> Optional[str]:
        """Get source data for a metric group with a single operation."""
        try:
            if 'command' in group_config:
                result = await self.command_executor.execute_command(
                    group_config['command'],
                    self.user_context if self.user_context else None
                )
                return result.output if result.success else None
                
            elif 'source' in group_config:
                source_type = group_config.get('source_type', 'file')
                if source_type == 'file':
                    return self.file_watcher.get_content(
                        group_config['source']
                    )
                # Add other source types (HTTP, etc.) here
                
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get source data: {e}")
            return None
    
    def _parse_metric_value(
        self,
        source_data: str,
        metric_config: Dict
    ) -> Optional[float]:
        """Parse individual metric value from group's source data."""
        try:
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
        group_prefix = group_config.get('prefix', '')
        
        for metric_name in group_config.get('metrics', {}):
            if metric_name in self.metrics:
                full_metric_name = (
                    f"{self.service_config.get('metric_prefix', '')}"
                    f"{group_prefix}{metric_name}"
                )
                results[full_metric_name] = self.metrics[metric_name]['last_value']
        
        return results

class MetricsCollector:
    """Main metrics collector managing multiple services."""
    
    METRICS_PREFIX = 'exporter'
    
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
        prefix = f"{self.METRICS_PREFIX}_"
        self._internal_metrics = {
            'collection_successful': Gauge(
                f'{prefix}collection_successful_total',
                'Total number of successful metric collections'
            ),
            'collection_errors': Gauge(
                f'{prefix}collection_errors_total',
                'Total number of metric collection errors'
            ),
            'collection_duration': Gauge(
                f'{prefix}collection_duration_seconds',
                'Duration of metric collection in seconds'
            ),
            'uptime': Gauge(
                f'{prefix}uptime_seconds',
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
                    if metric.get('name') == metric_name:
                        return metric.get('description', f"Metric {metric_name}")
        return f"Metric {metric_name}"

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Health Check Server
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class HealthCheckServer:
    """Enhanced health check server with comprehensive service information."""

    def __init__(self, metrics_collector: MetricsCollector, port: int, logger: logging.Logger):
        self.collector = metrics_collector
        self.port = port
        self.logger = logger
        self.httpd = None
        self.server_thread = None
        self._shutdown_event = threading.Event()
        self.start_time = datetime.now()

    def get_health_status(self) -> dict:
        """Generate comprehensive health status."""
        uptime_seconds = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'service': {
                'name': 'prometheus_metrics_exporter',
                'version': '3.0.0',
                'status': 'healthy' if self.collector.stats.is_healthy(
                    self.collector.config.get('exporter', {}).get('failure_threshold', 20)
                ) else 'unhealthy',
                'uptime_seconds': uptime_seconds,
                'uptime_formatted': self._format_uptime(uptime_seconds)
            },
            'runtime': {
                'python_version': sys.version.split()[0],
                'pid': os.getpid(),
                'hostname': socket.gethostname(),
                'start_time': self.start_time.isoformat(),
                'parallel_collection': bool(
                    self.collector.config.get('exporter', {}).get('parallel_collection')
                ),
                'max_workers': self.collector.config.get('exporter', {}).get('max_workers', 4)
            },
            'configuration': {
                'metrics_port': self.collector.config.get('exporter', {}).get('metrics_port'),
                'health_port': self.collector.config.get('exporter', {}).get('health_port'),
                'poll_interval_sec': self.collector.config.get('exporter', {}).get('poll_interval_sec'),
                'current_config': self._get_current_config(),
                'config_file': self._get_config_file_path()
            },
            'services': self._get_services_status(),
            'collection_stats': {
                'totals': {
                    'attempts': self.collector.stats.attempts,
                    'successful': self.collector.stats.successful,
                    'warnings': self.collector.stats.warnings,
                    'errors': self.collector.stats.errors,
                    'consecutive_failures': self.collector.stats.consecutive_failures
                },
                'timing': {
                    'last_collection_time': round(self.collector.stats.last_collection_time, 3),
                    'average_collection_time': round(self.collector.stats.get_average_collection_time(), 3),
                    'total_collection_time': round(self.collector.stats.total_collection_time, 3)
                },
                'success_rate': round(
                    (self.collector.stats.successful / self.collector.stats.attempts * 100)
                    if self.collector.stats.attempts > 0 else 0, 2
                )
            },
            'timestamp': datetime.now().isoformat()
        }

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime into human-readable string."""
        days, remainder = divmod(int(seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0 or days > 0:
            parts.append(f"{hours}h")
        if minutes > 0 or hours > 0 or days > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        return " ".join(parts)

    def _get_current_config(self) -> Dict[str, Any]:
        """Get sanitized current configuration."""
        try:
            # Deep copy the config to avoid modifying the original
            config = copy.deepcopy(self.collector.config)
            
            # Remove sensitive information
            self._sanitize_config(config)
            return config
        except Exception as e:
            self.logger.error(f"Failed to get current config: {e}")
            return {"error": "Failed to retrieve configuration"}

    def _sanitize_config(self, config: Dict[str, Any]) -> None:
        """Remove sensitive information from config."""
        sensitive_keys = ['token', 'password', 'secret', 'key']
        
        def sanitize_dict(d: Dict[str, Any]) -> None:
            for k, v in d.items():
                if any(sensitive in k.lower() for sensitive in sensitive_keys):
                    d[k] = "**REDACTED**"
                elif isinstance(v, dict):
                    sanitize_dict(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            sanitize_dict(item)

        sanitize_dict(config)

    def _get_config_file_path(self) -> str:
        """Get the path to the current config file."""
        script_path = os.path.abspath(sys.argv[0])
        return os.path.splitext(script_path)[0] + '.yml'

    def _get_services_status(self) -> dict:
        """Get detailed status of all configured services."""
        services_status = {}
        
        for service_name, collector in self.collector.service_collectors.items():
            service_config = collector.service_config
            
            # Get metric stats for this service
            metric_count = 0
            successful_metrics = 0
            for group in service_config.get('metric_groups', {}).values():
                metric_count += len(group.get('metrics', {}))
                for metric in group.get('metrics', {}).values():
                    if metric.get('name') in collector.metrics:
                        successful_metrics += 1

            services_status[service_name] = {
                'name': service_config.get('name', service_name),
                'description': service_config.get('description', ''),
                'status': 'active' if successful_metrics > 0 else 'inactive',
                'metrics': {
                    'total': metric_count,
                    'collecting': successful_metrics,
                    'success_rate': round(
                        (successful_metrics / metric_count * 100)
                        if metric_count > 0 else 0, 2
                    )
                },
                'execution_context': {
                    'run_as': service_config.get('run_as', {}).get('user', 'prometheus'),
                    'metric_prefix': service_config.get('metric_prefix', ''),
                    'expose_metrics': service_config.get('expose_metrics', True)
                },
                'metric_groups': self._get_metric_groups_status(collector)
            }
            
        return services_status

    def _get_metric_groups_status(self, collector: ServiceMetricsCollector) -> dict:
        """Get detailed status of metric groups for a service."""
        groups_status = {}
        
        for group_name, group_config in collector.service_config.get('metric_groups', {}).items():
            metrics_status = {}
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                metric_data = collector.metrics.get(metric_config['name'], {})
                
                metrics_status[metric_name] = {
                    'name': metric_config['name'],
                    'description': metric_config.get('description', ''),
                    'type': metric_config.get('type', 'gauge'),
                    'collection_frequency': metric_config.get('collection_frequency', 0),
                    'last_collection': datetime.fromtimestamp(
                        metric_data.get('last_collection', 0)
                    ).isoformat() if metric_data.get('last_collection') else None,
                    'last_value': metric_data.get('last_value'),
                    'category': metric_config.get('category', 'default')
                }
            
            groups_status[group_name] = {
                'prefix': group_config.get('prefix', ''),
                'ordinal': group_config.get('ordinal', 999),
                'metrics': metrics_status
            }
            
        return groups_status

    def create_health_app(self):
        """Create WSGI app for health check endpoint."""
        def health_app(environ, start_response):
            try:
                if environ['PATH_INFO'] == '/health':
                    health_status = self.get_health_status()
                    is_healthy = health_status['service']['status'] == 'healthy'
                    
                    status = '200 OK' if is_healthy else '503 Service Unavailable'
                    response = json.dumps(health_status, indent=2).encode('utf-8')
                    
                    headers = [
                        ('Content-Type', 'application/json'),
                        ('Content-Length', str(len(response)))
                    ]
                    start_response(status, headers)
                    return [response]
                
                start_response('404 Not Found', [('Content-Type', 'application/json')])
                response = json.dumps({
                    'error': 'Not Found',
                    'message': 'Only /health endpoint is available',
                    'timestamp': datetime.now().isoformat()
                }).encode('utf-8')
                return [response]
                
            except Exception as e:
                self.logger.error(f"Health check error: {e}")
                start_response('500 Internal Server Error', 
                             [('Content-Type', 'application/json')])
                response = json.dumps({
                    'error': 'Internal Server Error',
                    'message': str(e),
                    'timestamp': datetime.now().isoformat()
                }).encode('utf-8')
                return [response]

        return health_app

    def run(self):
        """Start the health check server in a separate thread."""
        try:
            app = self.create_health_app()
            self.httpd = make_server('', self.port, app)
            self.httpd.timeout = 1
            
            self.server_thread = threading.Thread(
                target=self._run_server,
                name="HealthCheckServer",
                daemon=True
            )
            self.server_thread.start()
            
            return self.httpd
            
        except Exception as e:
            self.logger.error(f"Failed to start health check server: {e}")
            raise

    def _run_server(self):
        """Run server with shutdown handling."""
        try:
            while not self._shutdown_event.is_set():
                try:
                    self.httpd.handle_request()
                except Exception as e:
                    if not self._shutdown_event.is_set():
                        self.logger.error(f"Health check request error: {e}")
        except Exception as e:
            if not self._shutdown_event.is_set():
                self.logger.error(f"Health check server error: {e}")

    def shutdown(self, timeout: float = 2.0):
        """Gracefully shutdown the server."""
        if not self.httpd:
            return
            
        try:
            self._shutdown_event.set()
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=timeout)
                
            try:
                # Send an empty request to unblock handle_request
                requests.get(f"http://localhost:{self.port}/health", timeout=0.1)
            except requests.RequestException:
                pass
                
            self.httpd.server_close()
            
        except Exception as e:
            self.logger.warning(f"Error during health server shutdown: {e}")

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Main Service Class and Entry Point
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricsExporter:
    """Main service class for Prometheus metrics exporter."""

    def __init__(self):
        self.running_under_systemd = bool(os.getenv('INVOCATION_ID'))
        self.shutdown_event = threading.Event()
        
        # Set up logging first, before any other initialization
        self.logger = self._setup_logging()
        
        # Now load configuration
        try:
            self.config = self._load_config()
            
            # Reinitialize logging with loaded config if available
            if 'logging' in self.config:
                self.logger = self._setup_logging(self.config['logging'])
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise
        
        # Initialize user management
        if os.geteuid() == 0:  # Only if running as root
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
        
        # Initialize remaining components
        self.metrics_collector = MetricsCollector(self.config, self.logger)
        self.health_server = HealthCheckServer(
            self.metrics_collector, 
            self.config['exporter']['health_port'],
            self.logger
        )
        self.health_httpd = None
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        self.logger.info("Metrics exporter initialized")

    def _setup_logging(self, config: Dict = None) -> logging.Logger:
        """Set up logging with optional configuration."""
        logger = logging.getLogger('prometheus_metrics_exporter')
        logger.setLevel(logging.DEBUG)  # Base level DEBUG to allow all messages
        
        # Get defaults or configured values
        if config:
            log_level = config.get('level', 'INFO')
            max_bytes = config.get('max_bytes', 10 * 1024 * 1024)
            backup_count = config.get('backup_count', 3)
        else:
            log_level = 'INFO'
            max_bytes = 10 * 1024 * 1024  # 10MB
            backup_count = 3
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s [%(process)d] [%(threadName)s] '
            '[%(name)s.%(funcName)s] [%(levelname)s] %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        log_file = os.path.join(script_dir, 'prometheus_metrics_exporter.log')
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # Journal handler for systemd
        if self.running_under_systemd:
            journal_handler = journal.JournaldLogHandler()
            journal_handler.setLevel(logging.INFO)
            journal_handler.setFormatter(formatter)
            logger.addHandler(journal_handler)
        
        return logger

    def _load_config(self) -> Dict[str, Any]:
        """Load and validate configuration."""
        config_path = self._get_config_path()
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
                
            if not config:
                raise MetricConfigurationError("Empty configuration file")
                
            # Validate required sections
            required_sections = ['exporter', 'services']
            for section in required_sections:
                if section not in config:
                    raise MetricConfigurationError(f"Missing required section: {section}")
            
            return config
            
        except Exception as e:
            raise MetricConfigurationError(f"Failed to load config: {e}")

    def _get_config_path(self) -> str:
        """Get configuration file path."""
        script_path = os.path.abspath(sys.argv[0])
        return os.path.splitext(script_path)[0] + '.yml'

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"Received {signal_name}, initiating shutdown...")
        if self.running_under_systemd:
            notify(Notification.STOPPING, f"Service stopping due to {signal_name}")
        self.shutdown_event.set()

    def check_ports(self) -> bool:
        """Check if required ports are available."""
        ports_to_check = [
            self.config['exporter']['metrics_port'],
            self.config['exporter']['health_port']
        ]
        
        for port in ports_to_check:
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
                    notify(Notification.STOPPING, "Service stopping - ports unavailable")
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
                    notify(Notification.STOPPING, "Service stopping - failed to start metrics server")
                return 1
            
            # Start health check server
            try:
                self.health_httpd = self.health_server.run()
                self.logger.info(
                    f"Started health check server on port "
                    f"{self.config['exporter']['health_port']}"
                )
            except Exception as e:
                self.logger.error(f"Failed to start health check server: {e}")
                if self.running_under_systemd:
                    notify(Notification.STOPPING, "Service stopping - failed to start health server")
                return 1
            
            # Notify systemd we're ready
            if self.running_under_systemd:
                notify(Notification.READY, "Metrics exporter ready")
            
            # Main loop
            while not self.shutdown_event.is_set():
                try:
                    loop_start = time.time()
                    
                    # Check for configuration updates
                    if self._config_changed():
                        self.logger.info("Configuration file changed, reloading...")
                        await self._reload_config()
                    
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
                    
        except Exception as e:
            self.logger.exception(f"Fatal error: {e}")
            if self.running_under_systemd:
                notify(Notification.STOPPING, "Service stopping due to error")
            return 1
            
        finally:
            await self.cleanup()
            return 0

    def _config_changed(self) -> bool:
        """Check if config file has been modified."""
        try:
            current_mtime = os.path.getmtime(self._get_config_path())
            if not hasattr(self, '_config_mtime'):
                self._config_mtime = current_mtime
                return False
            if current_mtime > self._config_mtime:
                self._config_mtime = current_mtime
                return True
            return False
        except Exception:
            return False

    async def _reload_config(self):
        """Reload configuration file."""
        try:
            new_config = self._load_config()
            self.config = new_config
            
            # Update user permissions if running as root
            if self.user_manager:
                self.user_manager.collect_service_users()
                self.user_manager.update_sudo_permissions()
            
            # Reinitialize collectors with new config
            self.metrics_collector = MetricsCollector(new_config, self.logger)
            
            self.logger.info("Configuration reloaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")

    async def cleanup(self):
        """Cleanup resources before shutdown."""
        try:
            if self.health_httpd:
                self.health_server.shutdown()
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

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