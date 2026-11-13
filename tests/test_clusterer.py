import pytest
from datetime import datetime, timezone
from src.alert_parser import AlertEvent
from src.clusterer import cluster_alerts, _elbow_k


@pytest.fixture
def alert_list():
    """Genera 20 alertas ficticias con 4 descripciones distintas."""
    descriptions = [
        "Intento de fuerza bruta SSH",
        "Escaneo de puertos detectado",
        "Acceso no autorizado a archivo",
        "Malware detectado en endpoint",
    ]
    alerts = []
    for i in range(20):
        alerts.append(
            AlertEvent(
                timestamp=datetime.now(timezone.utc),
                rule_id=f"rule-{i}",
                description=descriptions[i % 4],
                level=5 + (i % 5),
                agent_name=f"agent-{i % 3}",
                mitre_technique="T1110" if i % 2 == 0 else "T1046",
            )
        )
    return alerts


def test_cluster_returns_dict(alert_list):
    """Verifica que cluster_alerts devuelve un diccionario."""
    result = cluster_alerts(alert_list)
    assert isinstance(result, dict)


def test_cluster_count_in_range(alert_list):
    """El número de clusters debe estar entre 2 y 8."""
    result = cluster_alerts(alert_list)
    n = len(result)
    assert 2 <= n <= 8


def test_all_alerts_assigned(alert_list):
    """Todas las alertas deben aparecer en algún cluster."""
    result = cluster_alerts(alert_list)
    assigned = [alert for cluster in result.values() for alert in cluster]
    assert len(assigned) == len(alert_list)
    assert set(id(a) for a in assigned) == set(id(a) for a in alert_list)


def test_single_alert_returns_one_cluster():
    """Con una sola alerta, debe devolver un único cluster."""
    alert = AlertEvent(
        timestamp=datetime.now(timezone.utc),
        rule_id="rule-single",
        description="Alerta única",
        level=10,
        agent_name="agent-single",
        mitre_technique="T1059",
    )
    result = cluster_alerts([alert])
    assert len(result) == 1
    assert len(result[0]) == 1


def test_elbow_k_minimum(alert_list):
    """_elbow_k debe devolver al menos 2 cuando hay suficientes muestras."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    texts = [a.description for a in alert_list]
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(texts)
    k = _elbow_k(X, min_k=2, max_k=8)
    assert k >= 2
