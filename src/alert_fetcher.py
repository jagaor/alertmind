import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from models import AlertEvent

logger = logging.getLogger(__name__)


class WazuhConnectionError(RuntimeError):
    """Error lanzado cuando la API de Wazuh no responde o devuelve datos inválidos."""


class WazuhAuthError(RuntimeError):
    """Error lanzado cuando la autenticación contra la API de Wazuh falla."""


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MOCK_ALERTS_PATH = PROJECT_ROOT / "data" / "mock_alerts.json"

DEFAULT_TIMEOUT = 30.0
DEFAULT_LIMIT = 500


def fetch_alerts(source: str, config: Dict[str, Any]) -> List[AlertEvent]:
    """Obtiene alertas desde la fuente indicada y las normaliza a AlertEvent.

    Args:
        source: 'mock' para cargar el fichero de ejemplo o 'wazuh' para consultar la API.
        config: diccionario de configuración cargado desde config.yaml.

    Returns:
        Lista de AlertEvent normalizados y ordenados por timestamp descendente.
    """
    source_normalized = (source or "").strip().lower()
    if source_normalized == "mock":
        return _fetch_from_mock(config)
    if source_normalized == "wazuh":
        return _fetch_from_wazuh(config)
    raise ValueError(f"Fuente de alertas no soportada: {source!r}")


def _fetch_from_mock(config: Dict[str, Any]) -> List[AlertEvent]:
    """Carga las alertas desde data/mock_alerts.json y las normaliza."""
    path = Path(config.get("mock_path", MOCK_ALERTS_PATH))
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    if not path.exists():
        raise FileNotFoundError(f"No se encontró el fichero de alertas mock: {path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        raise WazuhConnectionError(f"JSON inválido en {path}: {exc}") from exc

    if isinstance(raw, dict):
        raw_list = raw.get("data", raw.get("alerts", []))
    elif isinstance(raw, list):
        raw_list = raw
    else:
        raise WazuhConnectionError("Formato de alertas mock no reconocido")

    return _parse_wazuh_response(raw_list)


def _fetch_from_wazuh(config: Dict[str, Any]) -> List[AlertEvent]:
    """Autentica contra Wazuh y descarga las alertas recientes."""
    wazuh_cfg = config.get("wazuh", {})
    base_url = wazuh_cfg.get("url")
    username = wazuh_cfg.get("username")
    password = wazuh_cfg.get("password")
    verify_ssl = bool(wazuh_cfg.get("verify_ssl", True))
    min_level = int(config.get("min_level", 5))
    limit = int(wazuh_cfg.get("limit", DEFAULT_LIMIT))
    timeout = float(wazuh_cfg.get("timeout", DEFAULT_TIMEOUT))

    if not base_url or not username or not password:
        raise WazuhConnectionError(
            "Faltan credenciales de Wazuh (url, username, password) en la configuración"
        )

    base_url = base_url.rstrip("/")

    try:
        with httpx.Client(verify=verify_ssl, timeout=timeout) as client:
            token = _authenticate(client, base_url, username, password)
            raw_alerts = _request_alerts(client, base_url, token, min_level, limit)
    except httpx.HTTPError as exc:
        raise WazuhConnectionError(f"Error de conexión con Wazuh: {exc}") from exc

    return _parse_wazuh_response(raw_alerts)


def _authenticate(
    client: httpx.Client, base_url: str, username: str, password: str
) -> str:
    """Obtiene un token JWT desde el endpoint de autenticación de Wazuh."""
    url = f"{base_url}/security/user/authenticate"
    try:
        response = client.post(url, auth=(username, password))
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise WazuhAuthError(
            f"Autenticación fallida contra Wazuh ({exc.response.status_code})"
        ) from exc

    payload = response.json()
    token = payload.get("data", {}).get("token")
    if not token:
        raise WazuhAuthError("Wazuh no devolvió token JWT en la respuesta")
    return token


def _request_alerts(
    client: httpx.Client, base_url: str, token: str, min_level: int, limit: int
) -> List[Dict[str, Any]]:
    """Solicita las alertas filtradas por nivel mínimo."""
    url = f"{base_url}/alerts"
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "q": f"rule.level>={min_level}",
        "limit": limit,
        "sort": "-timestamp",
    }

    try:
        response = client.get(url, headers=headers, params=params)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise WazuhConnectionError(
            f"Wazuh devolvió un error al consultar alertas ({exc.response.status_code})"
        ) from exc

    payload = response.json()
    data = payload.get("data", {})
    affected = data.get("affected_items")
    if affected is None:
        raise WazuhConnectionError("Respuesta de Wazuh sin campo 'affected_items'")
    return affected


def _parse_wazuh_response(raw: List[Dict[str, Any]]) -> List[AlertEvent]:
    """Convierte alertas crudas de Wazuh en objetos AlertEvent.

    Ignora entradas mal formadas y registra un aviso para cada una de ellas.
    """
    events: List[AlertEvent] = []
    for idx, item in enumerate(raw):
        try:
            event = _build_event(item)
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Alerta descartada en posición %d: %s", idx, exc)
            continue
        if event is not None:
            events.append(event)

    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events


def _build_event(item: Dict[str, Any]) -> Optional[AlertEvent]:
    """Construye un AlertEvent a partir de un diccionario de alerta Wazuh."""
    if not isinstance(item, dict):
        raise TypeError("Elemento de alerta no es un diccionario")

    rule = item.get("rule") or {}
    agent = item.get("agent") or {}
    mitre = rule.get("mitre") or {}

    rule_id = str(rule.get("id", ""))
    description = str(rule.get("description", "")).strip()
    level = int(rule.get("level", 0))
    timestamp = str(item.get("timestamp", "")).strip()
    agent_name = str(agent.get("name", "unknown"))

    techniques = mitre.get("id") or []
    mitre_technique = techniques[0] if techniques else None

    if not description:
        raise ValueError("Alerta sin descripción de regla")
    if not timestamp:
        raise ValueError("Alerta sin timestamp")

    return AlertEvent(
        timestamp=timestamp,
        rule_id=rule_id,
        description=description,
        level=level,
        agent_name=agent_name,
        mitre_technique=mitre_technique,
    )
