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

Configuration:
---------------------

exporter:
    metrics_port: 9101  # Prometheus metrics port
    health_port: 9102 # Health check port
    user: prometheus # User to run commands as
    collection:
        poll_interval_sec: 5  # Global collection interval
        max_workers: 4  # Parallel collection workers
        failure_threshold: 20  # Collection failures before unhealthy
        collection_timeout_sec: 30 # Timeout for collection operations
    logging:
        level: "DEBUG"  # Main logging level
        file_level: "DEBUG"  # File logging level
        console_level: "INFO"  # Console output level
        journal_level: "WARNING"  # Systemd journal level
        max_bytes: 10485760  # Log file size limit
        backup_count: 3  # Log file rotation count
        format: "%(asctime)s [%(process)d] [%(threadName)s] [%(name)s.%(funcName)s] [%(levelname)s] %(message)s"  # Log format
        date_format: "%Y-%m-%d %H:%M:%S"  # Timestamp format

services:
    service_name:  # Each service to monitor
        description: "Service description"
        run_as:  username # Optional username to execute commands
        metric_groups:
            group_name:  # Logical grouping of metrics that share a single command
                command: "shell command that produces output"  # Command to execute
                metrics:
                    metric_name:
                        type: "gauge|static|counter" # Required metric type declaration
                        description: "Metric description"
                        filter: "regex or jq-style filter"  # Text regex or JSON filter
                        content_type: "text|json"  # How to parse command output, default text
                        value: 1.0 # Optional, only specified for "static" metrics
                        value_on_error: 0.0  # Optional, override value on failure (static or gauge)
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
import subprocess
import sys
import threading
import time
from concurrent.futures import Future
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import (
    Awaitable, Any, Dict, List, Optional, 
    TYPE_CHECKING, Union
)

# Third party imports
from prometheus_client import (
   Counter, Gauge, make_wsgi_app, start_http_server
)
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
        if not path.exists():
            path.touch()
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

@dataclass
class ProgramConfig:
    """Program configuration with dynamic reloading support."""
    _source: ProgramSource
    _config: Dict[str, Any] = field(init=False)
    _last_load_time: float = field(init=False, default=0)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _running_under_systemd: bool = field(init=False)

    REQUIRED_SECTIONS = {'exporter', 'services'}
    DEFAULT_VALUES = {
        'exporter': {
            'metrics_port': 9101,
            'health_port': 9102,
            'user': 'prometheus',
            'collection': {
                'poll_interval_sec': 5,
                'max_workers': 4,
                'failure_threshold': 20,
                'collection_timeout_sec': 30
            },
            'logging': {
                'level': 'DEBUG',
                'max_bytes': 10485760,  # 10MB
                'backup_count': 3,
                'file_level': 'DEBUG',
                'console_level': 'INFO',
                'journal_level': 'WARNING',
                'format': '%(asctime)s [%(process)d] [%(threadName)s] [%(name)s.%(funcName)s] [%(levelname)s] %(message)s',
                'date_format': '%Y-%m-%d %H:%M:%S'
            }
        }
    }

    def __post_init__(self):
        """Initial load of configuration."""
        self._running_under_systemd = bool(os.getenv('INVOCATION_ID'))
        self.load()

    @property
    def exporter_user(self) -> str:
        """Get configured exporter user."""
        return self.exporter.get('user', 'prometheus')

    @property
    def running_under_systemd(self) -> bool:
        """Whether the program is running under systemd."""
        return self._running_under_systemd

    @property
    def collection_timeout(self) -> int:
        """Collection timeout in seconds."""
        return self.collection.get('collection_timeout_sec', 30)

    @property
    def exporter(self) -> Dict[str, Any]:
        """Exporter configuration section."""
        self._check_reload()
        return self._config['exporter']
    
    @property
    def services(self) -> Dict[str, Any]:
        """Services configuration section."""
        self._check_reload()
        return self._config['services']

    @property
    def logging(self) -> Dict[str, Any]:
        """Logging configuration section."""
        return self.exporter.get('logging', {})

    @property
    def collection(self) -> Dict[str, Any]:
        """Collection configuration section."""
        return self.exporter.get('collection', {})
    
    @property
    def metrics_port(self) -> int:
        """Metrics server port."""
        return self.exporter['metrics_port']
    
    @property
    def health_port(self) -> int:
        """Health check server port."""
        return self.exporter['health_port']
    
    @property
    def poll_interval(self) -> int:
        """Collection polling interval."""
        return self.collection.get('poll_interval_sec', 5)
    
    @property
    def max_workers(self) -> int:
        """Maximum parallel collection workers."""
        return self.collection.get('max_workers', 4)
    
    @property
    def failure_threshold(self) -> int:
        """Failure threshold for health checking."""
        return self.collection.get('failure_threshold', 20)

    def get_service(self, name: str) -> Optional[Dict[str, Any]]:
        """Get service configuration by name."""
        return self.services.get(name)

    def get_service_metrics(self, service_name: str, group_name: str) -> Dict[str, Any]:
        """Get metrics configuration for a service group."""
        service = self.get_service(service_name)
        if not service:
            return {}
        return service.get('metric_groups', {}).get(group_name, {}).get('metrics', {})

    def _merge_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configuration with default values."""
        result = deepcopy(self.DEFAULT_VALUES)
        for key, value in config.items():
            if isinstance(value, dict) and key in result:
                result[key].update(value)
            else:
                result[key] = value
        return result

    def _validate_metric_config(self, metric_name: str, metric_config: Dict[str, Any]) -> None:
        """Validate individual metric configuration."""
        if 'type' not in metric_config:  # Add this check
            raise MetricConfigurationError(
                f"Metric {metric_name} missing required field: type"
            )

        if 'description' not in metric_config:
            raise MetricConfigurationError(
                f"Metric {metric_name} missing required field: description"
            )
        
        # Validate metric type
        metric_type = MetricType.from_config(metric_config)
        
        if metric_type == MetricType.STATIC:
            if 'value' not in metric_config:
                raise MetricConfigurationError(
                    f"Static metric {metric_name} must specify a value"
                )
            if 'filter' in metric_config:
                raise MetricConfigurationError(
                    f"Static metric {metric_name} cannot have a filter"
                )
        else:  # gauge or counter
            if 'value' in metric_config:
                raise MetricConfigurationError(
                    f"{metric_type.value} metric {metric_name} cannot have a static value"
                )
            if 'filter' not in metric_config:
                raise MetricConfigurationError(
                    f"{metric_type.value} metric {metric_name} must specify a filter"
                )

    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration structure and types."""
        if not config:
            raise MetricConfigurationError("Empty configuration")
            
        if missing := self.REQUIRED_SECTIONS - set(config):
            raise MetricConfigurationError(f"Missing required sections: {missing}")
            
        # Validate exporter section
        exporter = config.get('exporter', {})
        if not isinstance(exporter.get('metrics_port', 0), int):
            raise MetricConfigurationError("Metrics port must be an integer")
            
        collection = exporter.get('collection', {})
        if not isinstance(collection.get('poll_interval_sec', 0), (int, float)):
            raise MetricConfigurationError("Poll interval must be a number")
            
        # Validate services section
        services = config.get('services', {})
        if not isinstance(services, dict):
            raise MetricConfigurationError("Services must be a dictionary")
            
        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                raise MetricConfigurationError(
                    f"Service {service_name} configuration must be a dictionary"
                )

        # Validate metrics configuration
        for service_name, service_config in services.items():
            for group_name, group_config in service_config.get('metric_groups', {}).items():
                for metric_name, metric_config in group_config.get('metrics', {}).items():
                    self._validate_metric_config(metric_name, metric_config)

    def load(self) -> None:
        """Load configuration from file with thread safety."""
        with self._lock:
            try:
                with open(self._source.config_path) as f:
                    config = yaml.safe_load(f)
                
                self._validate_config(config)
                config = self._merge_defaults(config)
                
                self._config = config
                self._last_load_time = self._source.config_path.stat().st_mtime
                
            except Exception as e:
                if not hasattr(self, '_config'):
                    raise MetricConfigurationError(f"Failed to load initial config: {e}")

    def _check_reload(self) -> None:
        """Check if config file has been modified and reload if needed."""
        try:
            current_mtime = self._source.config_path.stat().st_mtime
            if current_mtime > self._last_load_time:
                self.load()
        except Exception:
            pass

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class ProgramLogger:
    """Manages logging configuration and setup."""

    def __init__(
        self,
        source: ProgramSource,
        config: ProgramConfig
    ):
        self.source = source
        self.config = config
        self._logger = self._setup_logging()
        self._handlers = {}

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
    
    def set_level(self, level: Union[str, int]) -> None:
        """Set log level for all handlers."""
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
        """Remove a handler by name."""
        if name in self._handlers:
            self._logger.removeHandler(self._handlers[name])
            del self._handlers[name]
    
    def _get_formatter(self) -> logging.Formatter:
        """Create formatter using current settings."""
        return logging.Formatter(
            self.config.logging['format'],
            self.config.logging['date_format']
        )

    def _setup_logging(self) -> logging.Logger:
        """Set up logging with configuration from config file."""
        logger = logging.getLogger(self.source.logger_name)
        logger.handlers.clear()

        log_level = self.config.logging['level']
        logger.setLevel(log_level)
        formatter = self._get_formatter()
        
        # File handler
        file_handler = RotatingFileHandler(
            self.source.log_path,
            maxBytes=self.config.logging['max_bytes'],
            backupCount=self.config.logging['backup_count']
        )
        file_handler.setLevel(self.config.logging['file_level'])
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        self._handlers['file'] = file_handler
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.config.logging['console_level'])
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        self._handlers['console'] = console_handler
        
        # Journal handler for systemd
        if self.config.running_under_systemd:
            journal_handler = journal.JournaldLogHandler()
            journal_handler.setLevel(self.config.logging['journal_level'])
            journal_handler.setFormatter(formatter)
            logger.addHandler(journal_handler)
            self._handlers['journal'] = journal_handler
        
        return logger

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricType(Enum):
    """Types of metrics supported."""
    GAUGE = "gauge"    # A value that can go up and down (default)
    STATIC = "static"  # Fixed value that rarely changes
    COUNTER = "counter" # Value that only increases

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'MetricType':
        """Get metric type from config."""
        if 'type' in config:
            try:
                return cls(config['type'].lower())
            except ValueError:
                raise MetricConfigurationError(
                    f"Invalid metric type: {config['type']}. "
                    f"Must be one of: {[t.value for t in cls]}"
                )
        
        # Default to gauge unless static value present
        return cls.STATIC if 'value' in config else cls.GAUGE

@dataclass(frozen=True, eq=True)
class MetricIdentifier:
    """Structured metric identifier."""
    service: str
    group: str
    name: str
    type: MetricType
    description: str

    @property
    def prometheus_name(self) -> str:
        """Get prometheus-compatible metric name."""
        return f"{self.service}_{self.group}_{self.name}"

class ContentType(Enum):
    """Content types for data sources."""
    TEXT = "text" # Use regex pattern matching
    JSON = "json" # Use jq-style path filtering
    
    def parse_value(self, content: str, filter_expr: str, logger: logging.Logger) -> Optional[float]:
        """Parse content based on content type."""
        try:
            if self == ContentType.TEXT:
                match = re.search(filter_expr, content)
                return float(match.group(1)) if match else None
                
            elif self == ContentType.JSON:
                try:
                    data = json.loads(content)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON content: {e}")
                    return None
                    
                # Handle jq-style filter (e.g. ".status.block_height")
                try:
                    for key in filter_expr.strip('.').split('.'):
                        if not isinstance(data, dict):
                            logger.error(
                                f"Cannot access '{key}' in path '{filter_expr}': "
                                f"value '{data}' is not an object"
                            )
                            return None
                        if key not in data:
                            logger.error(
                                f"Key '{key}' not found in path '{filter_expr}': "
                                f"available keys {list(data.keys())}"
                            )
                            return None
                        data = data[key]
                        
                    try:
                        return float(data)
                    except (TypeError, ValueError) as e:
                        logger.error(
                            f"Could not convert value '{data}' to float"
                            f"at path '{filter_expr}'")
                        return None
                        
                except Exception as e:
                    logger.error(f"Error traversing JSON path: {e}")
                    return None
                
            return None
            
        except Exception as e:
            logger.warning(f"Failed to parse {self.value} response: {e}")
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
            f"# Generated at {datetime.now().isoformat()}",
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
        logger: logging.Logger
    ):
        self.service_name = service_name
        self.service_config = service_config
        self.logger = logger
        self.command_executor = CommandExecutor(logger)
        
        # Set up user context if specified
        self.user_context = None
        if 'run_as' in service_config:
            try:
                username = service_config['run_as']
                self.user_context = UserContext(username, logger)
            except Exception as e:
                self.logger.error(f"Failed to initialize user context for {service_name}: {e}")
    
    async def collect_metrics(self) -> Dict[MetricIdentifier, float]:
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
    ) -> Dict[MetricIdentifier, float]:
        """Collect all metrics in a group from a single source read."""
        self.logger.debug(f"Starting collection for group {group_name}")
        
        try:
            # Get the source data for the group
            command = group_config.get('command')
            if not command:
                self.logger.debug(f"No command specified for group {group_name}")
                return {}

            result = await self.command_executor.execute_command(
                command,
                self.user_context
            )

            source_data = result.output if result.success else None
            if source_data is None:
                self.logger.debug(f"No source data for group {group_name}")
                return {}

            results = {}
            for metric_name, metric_config in group_config.get('metrics', {}).items():
                try:
                    metric_type = MetricType.from_config(metric_config)
                    identifier = MetricIdentifier(
                        service=self.service_name,
                        group=group_name,
                        name=metric_name,
                        type=metric_type,
                        description=metric_config.get('description', f'Metric {metric_name}')
                    )

                    value = self._parse_metric_value(source_data, metric_config, metric_type)
                    if value is not None:
                        results[identifier] = value

                except Exception as e:
                    self.logger.error(f"Failed to parse metric {metric_name}: {e}")
                    
            return results
                
        except Exception as e:
            self.logger.error(f"Failed to collect group {group_name}: {e}")
            return {}
    
    def _parse_metric_value(
        self,
        source_data: str,
        metric_config: Dict,
        metric_type: MetricType
    ) -> Optional[float]:
        """Parse individual metric value from group's source data."""
        try:
            # Handle static metrics
            if metric_type == MetricType.STATIC:
                if 'value' not in metric_config:
                    self.logger.error("Static metric must specify a value")
                    return None
                return float(metric_config['value'])
            
            # Handle gauge and counter metrics
            if source_data is None:
                self.logger.debug("No source data available")
                return metric_config.get('value_on_error')
            
            if 'filter' not in metric_config:
                self.logger.error(f"{metric_type.value} metric must specify a filter")
                return None

            content_type = metric_config.get('content_type', 'text')
            content_type_enum = ContentType(content_type)
            value = content_type_enum.parse_value(
                source_data,
                metric_config['filter'],
                self.logger
            )
            
            if value is None and 'value_on_error' in metric_config:
                return metric_config['value_on_error']
            
            return value
            
        except Exception as e:
            self.logger.error(f"Failed to parse value: {e}")
            if 'value_on_error' in metric_config:
                return metric_config['value_on_error']
            return None

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricsCollector:
    """Main metrics collector managing multiple services."""
    
    def __init__(self, config: ProgramConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.stats = CollectionStats()
        self.service_collectors: Dict[str, ServiceMetricsCollector] = {}

        self._prometheus_metrics: Dict[MetricIdentifier, Union[Gauge, Counter]] = {}
        self._previous_values: Dict[MetricIdentifier, float] = {}
        self.start_time = datetime.now()
        self.collection_manager = CollectionManager(config, logger)
        
        # Initialize collectors for each service
        self._initialize_collectors()
        
        # Set up internal metrics
        self._setup_internal_metrics()
    
    def _initialize_collectors(self):
        """Initialize collectors for each service."""
        for service_name, service_config in self.config.services.items():
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
            service_results = await self.collection_manager.collect_services(
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
    
    def _create_prometheus_metric(
        self,
        identifier: MetricIdentifier
    ) -> Union[Gauge, Counter]:
        """Create appropriate Prometheus metric based on type."""
        if identifier.type == MetricType.COUNTER:
            return Counter(identifier.prometheus_name, identifier.description)
        return Gauge(identifier.prometheus_name, identifier.description)

    def _update_prometheus_metrics(self, metrics: Dict[MetricIdentifier, float]):
        """Update Prometheus metrics with collected values."""
        for identifier, value in metrics.items():
            if identifier not in self._prometheus_metrics:
                self._prometheus_metrics[identifier] = self._create_prometheus_metric(identifier)
            
            if value is not None:
                metric = self._prometheus_metrics[identifier]
                if identifier.type == MetricType.COUNTER:
                    prev_value = self._previous_values.get(identifier, 0)
                    if value > prev_value:
                        metric.inc(value - prev_value)
                    self._previous_values[identifier] = value
                else:
                    metric.set(value)
    
    def _update_internal_metrics(self, successes: int, errors: int, duration: float):
        """Update internal metrics."""
        self._internal_metrics['collection_successful'].set(self.stats.successful)
        self._internal_metrics['collection_errors'].set(self.stats.errors)
        self._internal_metrics['collection_duration'].set(duration)
        self._internal_metrics['uptime'].set(self.get_uptime())
    
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
# Main Service Class and Entry Point
#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

class MetricsExporter:
    """Main service class for Prometheus metrics exporter."""
    
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
        self.shutdown_event = threading.Event()
        
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
        
        self.logger.info("Metrics exporter initialized")

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"Received {signal_name}, initiating shutdown...")
        if self.config.running_under_systemd:
            notify(Notification.STOPPING)
        self.shutdown_event.set()

    def check_ports(self) -> bool:
        """Check if required ports are available."""
        ports = [
            self.config.metrics_port,
            self.config.health_port
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
                if self.config.running_under_systemd:
                    notify(Notification.STOPPING)
                return 1

            # Start Prometheus metrics server
            try:
                start_http_server(self.config.metrics_port)
                self.logger.info(f"Started Prometheus metrics server on port {self.config.metrics_port}")
            except Exception as e:
                self.logger.error(f"Failed to start metrics server: {e}")
                if self.config.running_under_systemd:
                    notify(Notification.STOPPING)
                return 1
            
            # Notify systemd we're ready
            if self.config.running_under_systemd:
                notify(Notification.READY)
            
            # Main collection loop
            while not self.shutdown_event.is_set():
                try:
                    loop_start = time.time()
                    await self.metrics_collector.collect_all_metrics()
                    
                    elapsed = time.time() - loop_start
                    sleep_time = max(0, self.config.poll_interval - elapsed)
                    
                    if sleep_time > 0:
                        await asyncio.sleep(sleep_time)
                    else:
                        self.logger.warning(
                            f"Collection took longer than poll interval "
                            f"({elapsed:.2f}s > {self.config.poll_interval}s)"
                        )
                    
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}")
                    self.logger.debug("Exception details:", exc_info=True)
                    await asyncio.sleep(1)  # Avoid tight loop on persistent errors
            
            self.logger.info("Shutdown event received, stopping service")
            return 0
            
        except Exception as e:
            self.logger.exception(f"Fatal error in service: {e}")
            if self.config.running_under_systemd:
                notify(Notification.STOPPING)
            return 1
            
        finally:
            self.logger.info("Service shutdown complete")

#-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~

async def main():
    """Entry point for the metrics exporter service."""
    try:
        source = ProgramSource()
        config = ProgramConfig(source)
        logger = ProgramLogger(source, config).logger

        try:
            exporter = MetricsExporter(source, config, logger)
            return await exporter.run()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            return 0
        except Exception as e:
            logger.error(f"Failed to start metrics exporter: {e}")
            return 1

    except Exception as e:
        # Only use print for catastrophic failures in logger setup
        print(f"Fatal error during startup: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))