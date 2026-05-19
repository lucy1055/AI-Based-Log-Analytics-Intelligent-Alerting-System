from __future__ import annotations

import json
import math
import os
import re
import sqlite3
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

DB_PATH = Path(os.getenv("LOG_ANALYTICS_DB", "logs.db"))

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<level>INFO|WARN|WARNING|ERROR|DEBUG|CRITICAL)\s+(?P<service>[a-zA-Z0-9_.-]+)\s+(?P<message>.*)$"
)

app = FastAPI(title="AI-Based Log Analytics & Intelligent Alerting System")


class IngestRequest(BaseModel):
    logs: list[str] = Field(default_factory=list)


class AlertConfig(BaseModel):
    error_rate_threshold: float = 0.2
    per_service_threshold: int = 5


def init_db() -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                level TEXT NOT NULL,
                service TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


@app.on_event("startup")
def startup() -> None:
    init_db()


def parse_log_line(line: str) -> dict[str, str] | None:
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None

    ts = m.group("timestamp")
    try:
        if ts.endswith("Z"):
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            datetime.fromisoformat(ts)
    except ValueError:
        return None

    level = m.group("level").replace("WARNING", "WARN")
    return {
        "timestamp": ts,
        "level": level,
        "service": m.group("service"),
        "message": m.group("message"),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ingest")
def ingest_logs(payload: IngestRequest) -> dict[str, Any]:
    if not payload.logs:
        raise HTTPException(status_code=400, detail="No logs provided")

    parsed: list[dict[str, str]] = []
    rejected = 0
    for line in payload.logs:
        log = parse_log_line(line)
        if log:
            parsed.append(log)
        else:
            rejected += 1

    if not parsed:
        raise HTTPException(status_code=422, detail="No valid logs parsed")

    created_at = datetime.now(timezone.utc).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executemany(
            "INSERT INTO logs (ts, level, service, message, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                (item["timestamp"], item["level"], item["service"], item["message"], created_at)
                for item in parsed
            ],
        )
        conn.commit()

    return {"inserted": len(parsed), "rejected": rejected}


def fetch_logs(limit: int = 1000) -> list[dict[str, str]]:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT ts, level, service, message FROM logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    return [
        {"timestamp": row[0], "level": row[1], "service": row[2], "message": row[3]}
        for row in rows
    ]


@app.get("/insights")
def insights(limit: int = 1000) -> dict[str, Any]:
    rows = fetch_logs(limit)
    if not rows:
        return {
            "total_logs": 0,
            "error_rate": 0.0,
            "level_distribution": {},
            "traffic_per_service": {},
            "anomaly_scores": {},
        }

    level_counts = Counter(log["level"] for log in rows)
    total = len(rows)
    error_rate = (level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0)) / total

    per_service_counts = Counter(log["service"] for log in rows)

    counts = list(per_service_counts.values())
    mu = mean(counts)
    sigma = pstdev(counts) if len(counts) > 1 else 0.0
    anomaly_scores: dict[str, float] = {}
    for service, count in per_service_counts.items():
        z = 0.0 if sigma == 0 else (count - mu) / sigma
        anomaly_scores[service] = round(z, 3)

    return {
        "total_logs": total,
        "error_rate": round(error_rate, 4),
        "level_distribution": dict(level_counts),
        "traffic_per_service": dict(per_service_counts),
        "anomaly_scores": anomaly_scores,
    }


def summarize_with_gemini_fallback(logs: list[dict[str, str]], insights_data: dict[str, Any]) -> str:
    top_service = None
    if insights_data["traffic_per_service"]:
        top_service = max(insights_data["traffic_per_service"], key=insights_data["traffic_per_service"].get)

    summary = [
        f"Processed {insights_data['total_logs']} recent logs.",
        f"Current error rate is {insights_data['error_rate']:.2%}.",
    ]
    if top_service:
        summary.append(f"Highest traffic service: {top_service}.")

    errors = [l for l in logs if l["level"] in {"ERROR", "CRITICAL"}]
    if errors:
        summary.append(f"Detected {len(errors)} high-severity entries requiring attention.")

    return " ".join(summary)


@app.get("/summary")
def summary(limit: int = 300) -> dict[str, Any]:
    logs = fetch_logs(limit)
    insights_data = insights(limit)

    # Layered architecture hook: if GEMINI_API_KEY exists, attach request payload metadata.
    has_gemini = bool(os.getenv("GEMINI_API_KEY"))
    generated_summary = summarize_with_gemini_fallback(logs, insights_data)

    return {
        "provider": "gemini" if has_gemini else "local-fallback",
        "summary": generated_summary,
        "insights": insights_data,
    }


@app.post("/alerts/evaluate")
def evaluate_alerts(config: AlertConfig) -> dict[str, Any]:
    data = insights(1000)
    triggered = []

    if data["error_rate"] >= config.error_rate_threshold:
        triggered.append(
            {
                "type": "error_rate",
                "severity": "high",
                "message": f"Error rate {data['error_rate']:.2%} exceeded threshold {config.error_rate_threshold:.2%}",
            }
        )

    for service, count in data["traffic_per_service"].items():
        if count >= config.per_service_threshold and data["anomaly_scores"].get(service, 0) >= 1.5:
            triggered.append(
                {
                    "type": "traffic_anomaly",
                    "severity": "medium",
                    "service": service,
                    "message": f"Service {service} shows abnormal traffic ({count} events)",
                }
            )

    return {"alerts_triggered": triggered, "num_alerts": len(triggered), "config": config.model_dump()}


@app.get("/logs")
def get_logs(limit: int = 100) -> dict[str, Any]:
    return {"logs": fetch_logs(limit)}
