import pytest
from datetime import datetime, timezone
from src.alert_parser import AlertEvent
from src.summarizer import build_summary, SummaryResult


@pytest.fixture
def sample_alerts():
    """Devuelve una lista de 5 AlertEvent con nivel 12."""
    now = datetime.now(timezone.utc)
    return [
        AlertEvent(
            timestamp=now,
            rule_id="5710",
            description="Intento de fuerza bruta SSH",
            level=12,
            agent_name="server-01",
            mitre_technique="T1110",
        ),
        AlertEvent(
            timestamp=now,
            rule_id="5710",
            description="Intento de fuerza bruta SSH",
            level=12,
            agent_name="server-01",
            mitre_technique="T1110",
        ),
        AlertEvent(
            timestamp=now,
            rule_id="5710",
            description="Intento de fuerza bruta SSH",
            level=12,
            agent_name="server-02",
            mitre_technique="T1110",
        ),
        AlertEvent(
            timestamp=now,
            rule_id="5712",
            description="Acceso SSH exitoso tras múltiples fallos",
            level=12,
            agent_name="server-01",
            mitre_technique="T1078",
        ),
        AlertEvent(
            timestamp=now,
            rule_id="5710",
            description="Intento de fuerza bruta SSH",
            level=12,
            agent_name="server-03",
            mitre_technique="T1110",
        ),
    ]


@pytest.fixture
def llm_response():
    """Respuesta simulada del LLM."""
    return {
        "text": "Ataque de fuerza bruta detectado. Bloquear la IP inmediatamente.",
        "tokens": 150,
        "latency_s": 2.1,
    }


def test_severity_critico(sample_alerts, llm_response):
    """Nivel >= 13 debe producir severidad CRÍTICO."""
    alerts = [a for a in sample_alerts]
    alerts[0].level = 13
    result = build_summary(alerts, llm_response)
    assert result.severity == "CRÍTICO"


def test_severity_alto(sample_alerts, llm_response):
    """Nivel 11 debe producir severidad ALTO."""
    alerts = [a for a in sample_alerts]
    alerts[0].level = 11
    result = build_summary(alerts, llm_response)
    assert result.severity == "ALTO"


def test_severity_bajo(sample_alerts, llm_response):
    """Nivel 5 debe producir severidad BAJO."""
    alerts = [a for a in sample_alerts]
    alerts[0].level = 5
    result = build_summary(alerts, llm_response)
    assert result.severity == "BAJO"


def test_dominant_rule_id(sample_alerts, llm_response):
    """El rule_id más frecuente debe ser el dominante."""
    result = build_summary(sample_alerts, llm_response)
    assert result.dominant_rule_id == "5710"


def test_affected_agents_unique(sample_alerts, llm_response):
    """La lista de agentes afectados no debe contener duplicados."""
    result = build_summary(sample_alerts, llm_response)
    assert len(result.affected_agents) == len(set(result.affected_agents))


def test_summary_result_is_valid_pydantic(sample_alerts, llm_response):
    """build_summary debe devolver un SummaryResult válido sin ValidationError."""
    result = build_summary(sample_alerts, llm_response)
    assert isinstance(result, SummaryResult)
    assert result.cluster_id is not None
    assert result.resumen != ""
    assert result.next_step != ""