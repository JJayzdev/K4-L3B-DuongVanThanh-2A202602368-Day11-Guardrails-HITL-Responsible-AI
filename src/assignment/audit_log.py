"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input metadata and return the correlation ID used for it."""
        correlation_id = request_id or user_id
        self._open[correlation_id] = {
            "request_id": correlation_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_monotonic": time.perf_counter(),
        }
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete an interaction and append it to the audit trail."""
        correlation_id = request_id or user_id
        pending = self._open.pop(correlation_id, None)
        if pending is None and request_id is None:
            # Compatibility for callers that key a request by user ID.
            pending = self._open.pop(user_id, None)

        now = time.perf_counter()
        entry = {
            "request_id": correlation_id,
            "user_id": user_id,
            "input": pending.get("input", "") if pending else "",
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "started_at": pending.get("started_at") if pending else None,
            "completed_at": utc_now_iso(),
            "latency_ms": round(
                (now - pending["started_monotonic"]) * 1000, 3
            ) if pending else 0.0,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
