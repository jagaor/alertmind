import os
from pathlib import Path
from typing import Any, Dict

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "wazuh": {
        "url": "https://localhost:55000",
        "user": "wazuh",
        "password": "wazuh",
        "verify_ssl": False,
    },
    "ollama": {
        "url": "http://localhost:11434",
        "model": "mistral",
        "timeout_s": 60,
    },
    "alerts": {
        "min_level": 7,
        "lookback_minutes": 60,
        "max_per_cluster": 10,
    },
    "output": {
        "dir": "output",
    },
}

# Claves críticas que deben existir y no estar vacías.
REQUIRED_KEYS = [
    ("wazuh", "url"),
    ("ollama", "url"),
    ("ollama", "model"),
    ("alerts", "min_level"),
    ("alerts", "lookback_minutes"),
]


def _merge_defaults(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Fusiona recursivamente los valores por defecto con los del fichero."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_defaults(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """Carga la configuración desde un fichero YAML.

    Si el fichero no existe o está vacío, devuelve los valores por defecto
    razonables definidos en DEFAULT_CONFIG. Las variables de entorno
    WAZUH_PASSWORD y OLLAMA_MODEL, si están definidas, sobrescriben los
    valores del fichero para evitar secretos hardcodeados.
    """
    config_path = Path(path)
    if not config_path.is_file():
        cfg = _merge_defaults(DEFAULT_CONFIG, {})
    else:
        with config_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"El fichero de configuración {path} no contiene un mapeo YAML válido")
        cfg = _merge_defaults(DEFAULT_CONFIG, raw)

    # Sobrescritura por variables de entorno (sin secretos en el repo).
    env_password = os.environ.get("WAZUH_PASSWORD")
    if env_password:
        cfg.setdefault("wazuh", {})["password"] = env_password

    env_user = os.environ.get("WAZUH_USER")
    if env_user:
        cfg.setdefault("wazuh", {})["user"] = env_user

    env_model = os.environ.get("OLLAMA_MODEL")
    if env_model:
        cfg.setdefault("ollama", {})["model"] = env_model

    env_ollama_url = os.environ.get("OLLAMA_URL")
    if env_ollama_url:
        cfg.setdefault("ollama", {})["url"] = env_ollama_url

    env_wazuh_url = os.environ.get("WAZUH_URL")
    if env_wazuh_url:
        cfg.setdefault("wazuh", {})["url"] = env_wazuh_url

    return cfg


def validate_config(cfg: Dict[str, Any]) -> None:
    """Valida que la configuración contiene las claves críticas y tipos correctos.

    Lanza ValueError si falta alguna sección o clave obligatoria, o si los
    valores no son del tipo esperado.
    """
    if not isinstance(cfg, dict):
        raise ValueError("La configuración debe ser un diccionario")

    for section, key in REQUIRED_KEYS:
        if section not in cfg or not isinstance(cfg[section], dict):
            raise ValueError(f"Falta la sección de configuración '{section}'")
        if key not in cfg[section] or cfg[section][key] in (None, ""):
            raise ValueError(f"Falta la clave crítica '{section}.{key}' en la configuración")

    # Validaciones de tipo y rango para evitar valores absurdos.
    min_level = cfg["alerts"]["min_level"]
    if not isinstance(min_level, int) or not (0 <= min_level <= 16):
        raise ValueError("alerts.min_level debe ser un entero entre 0 y 16")

    lookback = cfg["alerts"]["lookback_minutes"]
    if not isinstance(lookback, int) or lookback <= 0:
        raise ValueError("alerts.lookback_minutes debe ser un entero positivo")

    max_per_cluster = cfg["alerts"].get("max_per_cluster", 10)
    if not isinstance(max_per_cluster, int) or max_per_cluster <= 0:
        raise ValueError("alerts.max_per_cluster debe ser un entero positivo")

    timeout = cfg["ollama"].get("timeout_s", 60)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("ollama.timeout_s debe ser un número positivo")
