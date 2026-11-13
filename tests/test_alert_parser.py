import pytest
from datetime import datetime, timedelta, UTC

from src.alert_parser import AlertEvent, normalize_alert, filter_alerts


def _raw_alert(level: int = 7, minutes_ago: int = 5, mitre: str | None = "T1059") -> dict:
    """Construye un dict de alerta cruda de Wazuh para los tests."""
    ts = (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()
    raw = {
        "timestamp": ts,
        "rule": {"id": "5710", "level": level, "description": "Intento de login fallido"},
        "agent": {"name": "srv-web-01"},
    }
    if mitre is not None:
        raw["rule"]["mitre"] = {"technique": [mitre]}
    return raw


def test_normalize_alert_basic():
    raw = _raw_alert(level=12, minutes_ago=3, mitre="T1110")
    event = normalize_alert(raw)

    assert isinstance(event, AlertEvent)
    assert event.rule_id == "5710"
    assert event.level == 12
    assert event.agent_name == "srv-web-01"
    assert event.description == "Intento de login fallido"
    assert event.mitre_technique == "T1110"
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None


def test_normalize_alert_missing_mitre():
    raw = _raw_alert(level=5, minutes_ago=10, mitre=None)
    event = normalize_alert(raw)

    assert event.mitre_technique is None
    assert event.level == 5


def test_filter_by_level():
    niveles = [3, 5, 7, 9, 10, 10, 12, 14, 15, 2]
    alertas = [normalize_alert(_raw_alert(level=n, minutes_ago=5)) for n in niveles]

    filtradas = filter_alerts(alertas, min_level=10, lookback_minutes=60)

    assert len(filtradas) == 4
    assert all(a.level >= 10 for a in filtradas)


def test_filter_by_lookback():
    recientes = [normalize_alert(_raw_alert(level=12, minutes_ago=30)) for _ in range(3)]
    antiguas = [normalize_alert(_raw_alert(level=12, minutes_ago=90)) for _ in range(3)]

    filtradas = filter_alerts(recientes + antiguas, min_level=10, lookback_minutes=60)

    assert len(filtradas) == 3
    ahora = datetime.now(UTC)
    for alerta in filtradas:
        assert (ahora - alerta.timestamp) <= timedelta(minutes=60)
