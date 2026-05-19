# AI-Based Log Analytics & Intelligent Alerting System

A Python + FastAPI + SQLite project for parsing server logs, surfacing analytics insights, and generating intelligent threshold-based alerts.

## Features

- Parse and ingest structured logs with regex + validation.
- Expose insights for error rate, level distributions, service traffic, and anomaly scores.
- Provide layered summary generation with a Gemini-ready hook and local fallback summarizer.
- Evaluate alerts using configurable thresholds.

## Log Format

`<ISO_TIMESTAMP> <LEVEL> <SERVICE> <MESSAGE>`

Example:

`2026-05-19T13:00:00Z ERROR api-gateway Timeout while calling billing-service`

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## API Endpoints

- `GET /health`
- `POST /ingest`
- `GET /insights`
- `GET /summary`
- `POST /alerts/evaluate`
- `GET /logs`
