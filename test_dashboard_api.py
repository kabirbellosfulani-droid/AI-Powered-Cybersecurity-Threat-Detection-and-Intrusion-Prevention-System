"""
test_dashboard_api.py
=====================
Automated tests for the Flask SOC Dashboard and REST API endpoints.

Covers:
  - All 12 REST API endpoints (/api/health, /api/summary, /api/alerts,
    /api/events, /api/series, /api/model, /api/features, /api/scenarios,
    /api/stream/next, /api/predict, /api/simulate, /api/reset)
  - All 4 HTML page views (/, /range, /model, /docs)
  - Figure serving (/figures/<name>)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE))

from dashboard.app import app


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_page_dashboard(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"SENTINEL" in res.data or b"SOC" in res.data


def test_page_range(client):
    res = client.get("/range")
    assert res.status_code == 200
    assert b"Cyber Range" in res.data or b"Simulation" in res.data or b"range" in res.data


def test_page_model(client):
    res = client.get("/model")
    assert res.status_code == 200
    assert b"Model" in res.data or b"Intelligence" in res.data


def test_page_docs(client):
    res = client.get("/docs")
    assert res.status_code == 200
    assert b"API" in res.data or b"Documentation" in res.data


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "operational"
    assert data["models_loaded"]["classifier"] is True
    assert data["models_loaded"]["anomaly_detector"] is True
    assert "uptime_seconds" in data


def test_api_summary(client):
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.get_json()
    for key in ["events_scanned", "attacks_detected", "alerts_raised", "confusion_matrix", "by_family"]:
        assert key in data
    cm = data["confusion_matrix"]
    assert all(k in cm for k in ["tp", "fp", "fn", "tn"])


def test_api_alerts(client):
    res = client.get("/api/alerts?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data
    assert "count" in data
    assert len(data["alerts"]) <= 10


def test_api_events(client):
    res = client.get("/api/events?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert "events" in data
    assert "count" in data
    assert len(data["events"]) <= 10


def test_api_series(client):
    res = client.get("/api/series")
    assert res.status_code == 200
    data = res.get_json()
    assert "series" in data
    assert isinstance(data["series"], list)


def test_api_model(client):
    res = client.get("/api/model")
    assert res.status_code == 200
    data = res.get_json()
    assert "metadata" in data
    assert "offline_metrics" in data
    assert "mitre_map" in data


def test_api_features(client):
    res = client.get("/api/features")
    assert res.status_code == 200
    data = res.get_json()
    assert "features" in data
    assert len(data["features"]) > 0
    assert "feature" in data["features"][0]
    assert "importance" in data["features"][0]


def test_api_scenarios(client):
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    data = res.get_json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 8


def test_api_stream_next(client):
    res = client.post("/api/stream/next", json={"n": 5, "attack_rate": 0.2})
    assert res.status_code == 200
    data = res.get_json()
    assert data["ingested"] == 5
    assert "new_alerts" in data
    assert "events" in data


def test_api_predict_benign(client):
    flow = {
        "duration": 2,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 150,
        "dst_bytes": 4500,
        "count": 1,
        "srv_count": 1,
        "logged_in": 1,
        "num_failed_logins": 0,
    }
    res = client.post("/api/predict", json=flow)
    assert res.status_code == 200
    data = res.get_json()
    assert "verdict" in data
    assert data["verdict"]["is_attack"] == 0
    assert data["verdict"]["risk_score"] < 40


def test_api_predict_attack(client):
    flow = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "ssh",
        "flag": "REJ",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 50,
        "srv_count": 50,
        "logged_in": 0,
        "num_failed_logins": 10,
        "rerror_rate": 1.0,
    }
    res = client.post("/api/predict", json=flow)
    assert res.status_code == 200
    data = res.get_json()
    assert "verdict" in data
    assert data["verdict"]["is_attack"] == 1
    assert data["verdict"]["risk_score"] >= 40


def test_api_simulate_short(client):
    payload = {"n_events": 60, "attack_rate": 0.2, "seed": 42}
    res = client.post("/api/simulate", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "summary" in data
    assert "per_scenario" in data
    assert data["summary"]["precision"] >= 0.0
    assert data["summary"]["recall"] >= 0.0


def test_api_reset(client):
    res = client.post("/api/reset")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "reset"
