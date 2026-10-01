# SIEM Adapters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After ingest, send each `fusion-siem.v1` envelope to one destination: Splunk HEC, QRadar TCP LEEF, Rapid7 InsightIDR webhook, or Any (generic HTTPS JSON).

**Architecture:** Resolve `FUSION_SIEM_DESTINATION` (with backward-compatible Any when only `FORWARD_URL` is set). Always write JSONL. Call exactly one adapter. Mark seen only after a successful send. Map `DestinationNotConfigured` to HTTP 503 (no JSONL) and send failures to HTTP 502 (JSONL written, not seen).

**Tech Stack:** FastAPI, pydantic-settings, httpx, stdlib `socket`, existing localhost Settings UI.

## Global Constraints

- One destination per process; no Sentinel; no QRadar TLS/UDP; no hot-reload.
- Envelope schema stays `fusion-siem.v1`.
- LEEF vendor/product are `FusionSIEM` / `Bridge` (not Sophos).
- Splunk auth is `Authorization: Splunk <token>`; Rapid7 is `X-Api-Key`; Any stays Bearer.
- UI remains loopback-only. Save writes `.env` and still requires restart.
- Adapter timeout is 30s. No internal retry.

## Files

- Create: `src/fusion_siem/adapters/errors.py`
- Create: `src/fusion_siem/adapters/destination.py`
- Create: `src/fusion_siem/adapters/splunk.py`
- Create: `src/fusion_siem/adapters/qradar.py`
- Create: `src/fusion_siem/adapters/rapid7.py`
- Create: `tests/test_destinations.py`
- Modify: `src/fusion_siem/config.py`, `pipeline.py`, `app.py`, `envfile.py`, `ui.py`, `adapters/https.py`, `adapters/__init__.py`
- Modify: `src/fusion_siem/web/index.html`, `app.js`, `app.css`
- Modify: `tests/test_ui.py`, `.env.example`, `README.md`

### Task 1: Destination resolve + Splunk/Rapid7/QRadar/Any adapters

TDD in `tests/test_destinations.py`: effective destination defaults; HEC wrapper + Splunk auth; Rapid7 `X-Api-Key`; LEEF line + TCP send; connect fail.

### Task 2: Pipeline and ingest status codes

TDD: none writes JSONL and seen; unset DESTINATION + FORWARD_URL uses Any; Splunk 503 → ingest 502, JSONL present, not seen; missing Splunk URL → ingest 503, no JSONL; duplicate skips forward.

### Task 3: Settings UI destination picker

TDD GET/PUT destination fields, masked tokens, unused vendor keys preserved. HTML Destination select; show only that destination’s fields.

### Task 4: Docs

README Local UI / Configuration; `.env.example` destination keys.
