"""Simple in-memory, thread-safe packet queue (Phase 2 scale)."""
from collections import deque
import threading

packet_queue = deque(maxlen=50000)
queue_lock = threading.Lock()