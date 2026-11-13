import time
from typing import List, Dict, Any, Optional

import httpx

from alert_parser import AlertEvent

SYSTEM_PROMPT = (
    "Eres un analista SOC experimentado. Recibes un grupo de alertas de seguridad "
    "correlacionadas. Resume qué está pasando en 2-3 frases claras y propón UNA "
    "acción concreta e inmediata para el analista."
)


def _build_user_prompt(alerts: List[AlertEvent]) -> str:
    """Construye el prompt del usuario a partir del cluster de alertas."""
    if not alerts:
        return "No hay alertas en este grupo."

    num_alerts = len(alerts)
    timestamps = sorted(a.timestamp for a in alerts if a.timestamp)
    if timestamps:
        window = f"{timestamps[0]} -> {timestamps[-1]}"
    else:
        window = "desconocida"

    # Top-10 descripciones más frecuentes (o únicas si hay menos)
    descriptions = [a.description for a in alerts if a.description]
    unique_descriptions = list(dict.fromkeys(descriptions))[:10]
    desc_lines = "\n".join(f"- {d}" for d in unique_descriptions)

    max_level = max((a.level for a in alerts if a.level is not None), default=0)
    agent_names = sorted({a.agent_name for a in alerts if a.agent_name})
    agents_str = ", ".join(agent_names) if agent_names else "desconocidos"

    mitre_techniques = sorted({a.mitre_technique for a in alerts if a.mitre_technique})
    mitre_str = ", ".join(mitre_techniques) if mitre_techniques else "no identificada"

    prompt = (
        f"Número de alertas: {num_alerts}\n"
        f"Ventana temporal: {window}\n"
        f"Nivel máximo: {max_level}\n"
        f"Agentes afectados: {agents_str}\n"
        f"Técnica MITRE: {mitre_str}\n\n"
        f"Descripciones principales:\n{desc_lines}\n\n"
        "Proporciona un resumen y una acción recomendada."
    )
    return prompt


def query_llm(
    cluster_alerts: List[AlertEvent],
    model: str,
    ollama_url: str = "http://localhost:11434",
) -> Dict[str, Any]:
    """
    Envía un cluster de alertas al modelo Ollama local y devuelve la respuesta.

    Devuelve un dict con:
        - text: texto generado o mensaje de error de conexión.
        - tokens: suma de eval_count y prompt_eval_count.
        - latency_s: latencia de la llamada en segundos.
    """
    user_prompt = _build_user_prompt(cluster_alerts)
    full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"

    payload = {
        "model": model,
        "prompt": full_prompt,
        "stream": False,
    }

    start = time.perf_counter()
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(f"{ollama_url}/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
        latency = time.perf_counter() - start
        return {
            "text": f"Error de conexión con Ollama: {exc}",
            "tokens": 0,
            "latency_s": round(latency, 3),
        }
    except Exception as exc:
        latency = time.perf_counter() - start
        return {
            "text": f"Error inesperado al contactar con Ollama: {exc}",
            "tokens": 0,
            "latency_s": round(latency, 3),
        }

    latency = time.perf_counter() - start
    text = data.get("response", "")
    eval_count = data.get("eval_count", 0) or 0
    prompt_eval_count = data.get("prompt_eval_count", 0) or 0
    tokens = int(eval_count) + int(prompt_eval_count)

    return {
        "text": text,
        "tokens": tokens,
        "latency_s": round(latency, 3),
    }
