"""
A2A task lifecycle (Slice 3).

Turns one-shot judge/redteam calls into first-class tasks with a state machine:

    submitted → working → completed
                       ↘ failed
    (any non-terminal) → canceled
    (working)          → input-required  [reserved for multi-turn, Slice 4]

One evaluation = one task. The service creates a task, processes it in the
background, and the caller polls until a terminal state. Sara's `.judge()` /
`.run_session()` surface is unaffected — this is an additive async path.

In-memory store; ClickHouse persistence is # A.5-full.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class TaskState(str, Enum):
    submitted = "submitted"
    working = "working"
    input_required = "input-required"
    completed = "completed"
    failed = "failed"
    canceled = "canceled"


TERMINAL = {TaskState.completed.value, TaskState.failed.value, TaskState.canceled.value}
VALID_KINDS = {"judge", "redteam"}


@dataclass
class Task:
    task_id: str
    kind: str                       # 'judge' | 'redteam'
    state: str
    input: dict
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


class TaskStore:
    """In-memory task store. # A.5-full: swap for a ClickHouse-backed store."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    def create(self, kind: str, task_input: dict) -> Task:
        task = Task(
            task_id=uuid.uuid4().hex[:16],
            kind=kind,
            state=TaskState.submitted.value,
            input=dict(task_input),
        )
        self._tasks[task.task_id] = task
        return task

    def get(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)

    def update(self, task_id: str, **fields) -> Optional[Task]:
        task = self._tasks.get(task_id)
        if task is None:
            return None
        for k, v in fields.items():
            setattr(task, k, v)
        task.updated_at = time.time()
        return task

    def cancel(self, task_id: str) -> Optional[Task]:
        """Best-effort cancel: only if the task hasn't reached a terminal state."""
        task = self._tasks.get(task_id)
        if task is None or task.state in TERMINAL:
            return task
        return self.update(task_id, state=TaskState.canceled.value)

    def list(self) -> list[Task]:
        return list(self._tasks.values())


async def process_task(store: TaskStore, task_id: str, judge_backend, redteam_backend) -> None:
    """Run a task to a terminal state. Cancellation-aware: if the task was
    canceled while running, the terminal result is not written over it."""
    task = store.get(task_id)
    if task is None or task.state in TERMINAL:
        return
    store.update(task_id, state=TaskState.working.value)
    try:
        if task.kind == "judge":
            verdict = await judge_backend().judge(**task.input)
            result = asdict(verdict)
        elif task.kind == "redteam":
            report = await redteam_backend().run_session(**task.input)
            result = asdict(report)
        else:
            raise ValueError(f"unknown task kind: {task.kind!r}")
        if store.get(task_id).state == TaskState.canceled.value:
            return
        store.update(task_id, state=TaskState.completed.value, result=result)
    except Exception as exc:  # pragma: no cover - defensive
        if store.get(task_id).state == TaskState.canceled.value:
            return
        store.update(task_id, state=TaskState.failed.value, error=str(exc))
