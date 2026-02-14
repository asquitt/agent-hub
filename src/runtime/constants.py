from __future__ import annotations

# Sandbox states
SANDBOX_PENDING = "pending"
SANDBOX_PROVISIONING = "provisioning"
SANDBOX_READY = "ready"
SANDBOX_EXECUTING = "executing"
SANDBOX_COMPLETED = "completed"
SANDBOX_FAILED = "failed"
SANDBOX_TERMINATED = "terminated"
SANDBOX_TIMED_OUT = "timed_out"

VALID_SANDBOX_STATES = {
    SANDBOX_PENDING,
    SANDBOX_PROVISIONING,
    SANDBOX_READY,
    SANDBOX_EXECUTING,
    SANDBOX_COMPLETED,
    SANDBOX_FAILED,
    SANDBOX_TERMINATED,
    SANDBOX_TIMED_OUT,
}

# Valid state transitions
SANDBOX_TRANSITIONS: dict[str, set[str]] = {
    SANDBOX_PENDING: {SANDBOX_PROVISIONING, SANDBOX_TERMINATED},
    SANDBOX_PROVISIONING: {SANDBOX_READY, SANDBOX_FAILED, SANDBOX_TERMINATED},
    SANDBOX_READY: {SANDBOX_EXECUTING, SANDBOX_TERMINATED, SANDBOX_COMPLETED},
    SANDBOX_EXECUTING: {SANDBOX_READY, SANDBOX_COMPLETED, SANDBOX_FAILED, SANDBOX_TERMINATED, SANDBOX_TIMED_OUT},
    SANDBOX_COMPLETED: set(),
    SANDBOX_FAILED: set(),
    SANDBOX_TERMINATED: set(),
    SANDBOX_TIMED_OUT: set(),
}

# Network modes
NETWORK_DISABLED = "disabled"
NETWORK_EGRESS_ONLY = "egress_only"
NETWORK_FULL = "full"
VALID_NETWORK_MODES = {NETWORK_DISABLED, NETWORK_EGRESS_ONLY, NETWORK_FULL}

# Resource defaults
DEFAULT_CPU_CORES = 0.25
DEFAULT_MEMORY_MB = 256
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_NETWORK_MODE = NETWORK_DISABLED
DEFAULT_DISK_IO_MB = 100

# Resource maximums
MAX_CPU_CORES = 4.0
MAX_MEMORY_MB = 8192
MAX_TIMEOUT_SECONDS = 3600
MAX_DISK_IO_MB = 4096

# Profile presets
DEFAULT_PROFILE_PRESETS: dict[str, dict[str, object]] = {
    "micro": {
        "name": "micro",
        "description": "Minimal sandbox: 0.25 CPU, 256MB RAM, 30s timeout, no network",
        "cpu_cores": 0.25,
        "memory_mb": 256,
        "timeout_seconds": 30,
        "network_mode": NETWORK_DISABLED,
        "disk_io_mb": 100,
    },
    "small": {
        "name": "small",
        "description": "Small sandbox: 0.5 CPU, 512MB RAM, 60s timeout, egress-only network",
        "cpu_cores": 0.5,
        "memory_mb": 512,
        "timeout_seconds": 60,
        "network_mode": NETWORK_EGRESS_ONLY,
        "disk_io_mb": 256,
    },
    "medium": {
        "name": "medium",
        "description": "Medium sandbox: 1 CPU, 1GB RAM, 300s timeout, full network",
        "cpu_cores": 1.0,
        "memory_mb": 1024,
        "timeout_seconds": 300,
        "network_mode": NETWORK_FULL,
        "disk_io_mb": 512,
    },
    "large": {
        "name": "large",
        "description": "Large sandbox: 2 CPU, 4GB RAM, 600s timeout, full network",
        "cpu_cores": 2.0,
        "memory_mb": 4096,
        "timeout_seconds": 600,
        "network_mode": NETWORK_FULL,
        "disk_io_mb": 1024,
    },
}

# Execution states
EXEC_PENDING = "pending"
EXEC_RUNNING = "running"
EXEC_COMPLETED = "completed"
EXEC_FAILED = "failed"
EXEC_TIMED_OUT = "timed_out"
VALID_EXEC_STATES = {EXEC_PENDING, EXEC_RUNNING, EXEC_COMPLETED, EXEC_FAILED, EXEC_TIMED_OUT}

# Log levels
LOG_DEBUG = "debug"
LOG_INFO = "info"
LOG_WARN = "warn"
LOG_ERROR = "error"
VALID_LOG_LEVELS = {LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR}
