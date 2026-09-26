"""
Pasha Local Agent - Read-Only System Collectors
"""

from agent.collectors.processes import collect_processes
from agent.collectors.persistence import collect_persistence
from agent.collectors.services import collect_services
from agent.collectors.scheduled_tasks import collect_scheduled_tasks
from agent.collectors.network import collect_network_connections
from agent.collectors.files import collect_security_files
from agent.collectors.browser import collect_browser_info

__all__ = [
    "collect_processes",
    "collect_persistence",
    "collect_services",
    "collect_scheduled_tasks",
    "collect_network_connections",
    "collect_security_files",
    "collect_browser_info",
]
