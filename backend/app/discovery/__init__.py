"""Safe repository inventory discovery."""

from app.discovery.engine import DiscoveryLimitError, discover_repository

__all__ = ["DiscoveryLimitError", "discover_repository"]
