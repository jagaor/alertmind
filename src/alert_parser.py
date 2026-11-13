import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class AlertEvent(BaseModel):
    """Evento de alerta normalizado procedente de Wazuh."""

    id: str = Field(..., description="Identificador único de la alerta")
    timestamp: datetime = Field(..., description="Fecha y hora del evento en UTC")
    rule_id: int = Field(..., description="ID de la regla que disparó la alerta")
    description: str = Field(..., description="Descripción legible de la regla")
    level: int = Field(..., ge=0, le=15, description="Nivel de severidad (0-15)")
    agent_name: str = Field(..., description="Nombre del agente que reportó la alerta")
    mitre_technique: Optional[str] = Field(
        None, description="Técnica MITRE ATT&CK asociada, si existe"
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value):
        """Acepta strings ISO 8601 y los convierte a datetime con zona UTC."""
        if isinstance(value, str):
            value = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @field_validator("id", mode="before")
    @classmethod
    def _ensure_id_str(cls, value):
        """Garantiza que el id sea siempre string."""
        return str(value)


# Mapeo de campos anidados de Wazuh a los atributos de AlertEvent.
# Se usa notación con puntos para recorrer el JSON de origen.
_FIELD_MAP = {
    "id": "_id",
    "timestamp": "_source.@timestamp",
    "rule_id": "_source.rule.id",
    "description": "_source.rule.description",
    "level": "_source.rule.level",
    "agent_name": "_source.agent.name",
    "mitre_technique": "_source.rule.mitre.technique",
}


def _get_nested(data: dict, path: str, default=None):
    """Recupera un valor anidado usando una ruta con puntos."""
    current = data
    for key in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def normalize_alert(raw: dict) -> AlertEvent:
    """Convierte una alerta cruda de Wazuh en un AlertEvent normalizado.

    Args:
        raw: Diccionario con la alerta tal y como la devuelve la API de Wazuh.

    Returns:
        Instancia de AlertEvent.

    Raises:
        ValueError: Si faltan campos obligatorios o el formato es inválido.
    """
    if not isinstance(raw, dict):
        raise ValueError("La alerta cruda debe ser un diccionario")

    extracted = {}
    for field_name, source_path in _FIELD_MAP.items():
        value = _get_nested(raw, source_path)
        if field_name == "mitre_technique" and isinstance(value, list):
            # Wazuh devuelve una lista de técnicas; tomamos la primera.
            value = value[0] if value else None
        extracted[field_name] = value

    # Validación explícita de campos obligatorios ausentes.
    required = ["id", "timestamp", "rule_id", "description", "level", "agent_name"]
    missing = [f for f in required if extracted.get(f) is None]
    if missing:
        raise ValueError(
            f"Alerta incompleta, faltan campos: {', '.join(missing)}"
        )

    try:
        return AlertEvent(**extracted)
    except Exception as exc:
        logger.error("Error normalizando alerta %s: %s", extracted.get("id"), exc)
        raise ValueError(f"Alerta inválida: {exc}") from exc


def filter_alerts(
    alerts: List[AlertEvent], min_level: int, lookback_minutes: int
) -> List[AlertEvent]:
    """Filtra alertas por nivel mínimo y ventana temporal hacia atrás.

    Args:
        alerts: Lista de AlertEvent normalizados.
        min_level: Nivel mínimo de severidad (inclusive).
        lookback_minutes: Minutos hacia atrás desde ahora para considerar la alerta.

    Returns:
        Lista filtrada de AlertEvent.
    """
    if lookback_minutes < 0:
        raise ValueError("lookback_minutes no puede ser negativo")

    now = datetime.now(timezone.utc)
    threshold = now - timedelta(minutes=lookback_minutes)

    filtered = [
        alert
        for alert in alerts
        if alert.level >= min_level and alert.timestamp >= threshold
    ]

    logger.debug(
        "Filtradas %d de %d alertas (min_level=%d, lookback=%d min)",
        len(filtered),
        len(alerts),
        min_level,
        lookback_minutes,
    )
    return filtered
