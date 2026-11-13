import re
from collections import Counter
from datetime import datetime
from typing import List, Literal

from pydantic import BaseModel, Field

from alert_parser import AlertEvent


class SummaryResult(BaseModel):
    """Resultado estructurado del resumen de un cluster de alertas."""

    cluster_id: int
    severity: Literal["CRÍTICO", "ALTO", "MEDIO", "BAJO"]
    alert_count: int
    dominant_rule_id: int
    dominant_rule_desc: str
    affected_agents: List[str]
    time_window_start: datetime
    time_window_end: datetime
    llm_summary: str
    next_step: str
    mitre_tactics: List[str]
    tokens_used: int = 0
    latency_s: float = 0.0


def _calcular_severidad(nivel_maximo: int) -> Literal["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
    """Determina la severidad del cluster según el nivel máximo de sus alertas."""
    if nivel_maximo >= 13:
        return "CRÍTICO"
    if nivel_maximo >= 10:
        return "ALTO"
    if nivel_maximo >= 7:
        return "MEDIO"
    return "BAJO"


def _extraer_next_step(texto: str) -> str:
    """Extrae la primera oración imperativa del texto LLM o, en su defecto, la última.

    Se considera imperativa si comienza por un verbo en infinitivo o imperativo
    (lista acotada de verbos habituales en respuesta a incidentes).
    """
    if not texto:
        return ""

    # Separar en oraciones por punto, interrogación o exclamación, conservando el delimitador
    oraciones = [o.strip() for o in re.split(r'(?<=[.!?])\s+', texto.strip()) if o.strip()]
    if not oraciones:
        return ""

    verbos_imperativos = {
        "revisa", "revisar", "verifica", "verificar", "comprueba", "comprobar",
        "bloquea", "bloquear", "aísla", "aislar", "investiga", "investigar",
        "actualiza", "actualizar", "rota", "rotar", "deshabilita", "deshabilitar",
        "habilita", "habilitar", "ejecuta", "ejecutar", "contacta", "contactar",
        "notifica", "notificar", "escala", "escalar", "documenta", "documentar",
        "analiza", "analizar", "inspecciona", "inspeccionar", "parchea", "parchear",
        "corrige", "corregir", "monitoriza", "monitorizar", "restaura", "restaurar",
        "aplica", "aplicar", "elimina", "eliminar", "cambia", "cambiar",
        "confirma", "confirmar", "valida", "validar", "restringe", "restringir",
    }

    for oracion in oraciones:
        primera_palabra = re.sub(r'^[^\wáéíóúüñ]+', '', oracion).split()[0].lower() if oracion.split() else ""
        if primera_palabra in verbos_imperativos:
            return oracion

    return oraciones[-1]


def build_summary(cluster_id: int, alerts: List[AlertEvent], llm_response: dict) -> SummaryResult:
    """Construye un SummaryResult a partir de las alertas del cluster y la respuesta del LLM.

    Args:
        cluster_id: Identificador del cluster.
        alerts: Lista de AlertEvent que componen el cluster (no vacía).
        llm_response: Diccionario con la respuesta del LLM. Se espera que contenga
            al menos 'response' (texto) y opcionalmente 'tokens_used' y 'latency_s'.

    Returns:
        SummaryResult con todos los campos calculados.
    """
    if not alerts:
        raise ValueError("El cluster no contiene alertas")

    # Severidad según nivel máximo
    nivel_maximo = max(a.level for a in alerts)
    severity = _calcular_severidad(nivel_maximo)

    # Regla dominante
    contador_reglas = Counter(a.rule_id for a in alerts)
    dominant_rule_id = contador_reglas.most_common(1)[0][0]
    # Descripción de la regla dominante: la primera alerta que la contenga
    dominant_rule_desc = next(
        (a.description for a in alerts if a.rule_id == dominant_rule_id), ""
    )

    # Agentes afectados (únicos, preservando orden de aparición)
    agentes_vistos = set()
    affected_agents: List[str] = []
    for alerta in alerts:
        if alerta.agent_name not in agentes_vistos:
            agentes_vistos.add(alerta.agent_name)
            affected_agents.append(alerta.agent_name)

    # Ventana temporal
    timestamps = [a.timestamp for a in alerts]
    time_window_start = min(timestamps)
    time_window_end = max(timestamps)

    # Texto del LLM
    llm_summary = llm_response.get("response", "").strip()

    # Next step
    next_step = _extraer_next_step(llm_summary)

    # Tácticas MITRE únicas
    mitre_tactics: List[str] = []
    tacticas_vistas = set()
    for alerta in alerts:
        if alerta.mitre_technique and alerta.mitre_technique not in tacticas_vistas:
            tacticas_vistas.add(alerta.mitre_technique)
            mitre_tactics.append(alerta.mitre_technique)

    return SummaryResult(
        cluster_id=cluster_id,
        severity=severity,
        alert_count=len(alerts),
        dominant_rule_id=dominant_rule_id,
        dominant_rule_desc=dominant_rule_desc,
        affected_agents=affected_agents,
        time_window_start=time_window_start,
        time_window_end=time_window_end,
        llm_summary=llm_summary,
        next_step=next_step,
        mitre_tactics=mitre_tactics,
        tokens_used=int(llm_response.get("tokens_used", 0)),
        latency_s=float(llm_response.get("latency_s", 0.0)),
    )
