"""
workers/queue.py
Simple in-memory task queue for async analysis jobs.
"""

import uuid
from typing import Optional

_tasks: dict = {}
_queue: list = []


def add_task(filename: str, data: bytes) -> str:
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "id":       task_id,
        "status":   "queued",
        "filename": filename,
        "data":     data,
        "result":   None,
        "error":    None,
    }
    _queue.append(task_id)
    return task_id


def get_task() -> Optional[str]:
    return _queue.pop(0) if _queue else None


def get_status(task_id: str) -> dict:
    return _tasks.get(task_id, {"error": "task not found"})


def set_result(task_id: str, result: dict) -> None:
    if task_id in _tasks:
        _tasks[task_id]["status"] = "done"
        _tasks[task_id]["result"] = result
        _tasks[task_id]["data"]   = None  # free memory


def set_error(task_id: str, error: str) -> None:
    if task_id in _tasks:
        _tasks[task_id]["status"] = "error"
        _tasks[task_id]["error"]  = error
        _tasks[task_id]["data"]   = None
