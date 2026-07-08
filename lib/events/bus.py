# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Lightweight Event Bus for decoupled component communication."""

import threading
from typing import Callable, Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from lib.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Event:
    """Base event class."""
    event_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)


class EventBus:
    """Lightweight pub/sub event bus for component decoupling."""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.RLock()
    
    def subscribe(self, event_type: str, handler: Callable[[Event], None]) -> None:
        """Subscribe a handler to an event type."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(handler)
            logger.debug(f"Subscribed handler to event type: {event_type}")
    
    def unsubscribe(self, event_type: str, handler: Callable[[Event], None]) -> None:
        """Unsubscribe a handler from an event type."""
        with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(handler)
                    logger.debug(f"Unsubscribed handler from event type: {event_type}")
                except ValueError:
                    logger.warning(f"Handler not found for event type: {event_type}")
    
    def publish(self, event: Event) -> None:
        """Publish an event to all subscribed handlers."""
        with self._lock:
            handlers = self._subscribers.get(event.event_type, []).copy()
        
        if handlers:
            logger.debug(f"Publishing event {event.event_type} to {len(handlers)} handlers")
            for handler in handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Error in event handler for {event.event_type}: {e}")
        else:
            logger.debug(f"No handlers for event type: {event.event_type}")
    
    def clear(self) -> None:
        """Clear all subscribers."""
        with self._lock:
            self._subscribers.clear()
            logger.debug("Cleared all event subscribers")


# Global event bus instance
_global_bus: Optional[EventBus] = None
_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _global_bus
    if _global_bus is None:
        with _bus_lock:
            if _global_bus is None:
                _global_bus = EventBus()
    return _global_bus


def reset_event_bus() -> None:
    """Reset the global event bus (useful for testing)."""
    global _global_bus
    with _bus_lock:
        if _global_bus is not None:
            _global_bus.clear()
            _global_bus = None
