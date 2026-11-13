from __future__ import annotations

from typing import Dict, List

import numpy as np
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer

from alert_parser import AlertEvent


def _elbow_k(X, max_k: int) -> int:
    """Selecciona el número de clusters usando el método del codo.

    Prueba K desde 2 hasta max_k y elige el primer K donde la reducción
    relativa de inercia respecto al K anterior cae por debajo del 20%.
    Si no se cumple para ningún K, devuelve max_k.
    """
    if max_k < 2:
        return 1

    inercias: List[float] = []
    for k in range(2, max_k + 1):
        modelo = KMeans(n_clusters=k, random_state=42, n_init=10)
        modelo.fit(X)
        inercias.append(float(modelo.inertia_))

    # La primera inercia corresponde a K=2; comparamos cada K con el anterior
    for idx in range(1, len(inercias)):
        reduccion = (inercias[idx - 1] - inercias[idx]) / inercias[idx - 1]
        if reduccion < 0.20:
            return idx + 1  # K = idx + 1 (porque idx=0 -> K=2)

    return max_k


def cluster_alerts(
    alerts: List[AlertEvent], max_clusters: int = 8
) -> Dict[int, List[AlertEvent]]:
    """Agrupa alertas por similitud de su descripción.

    Vectoriza el campo description con TF-IDF y aplica KMeans. El número
    de clusters se autoselecciona con el método del codo. Si hay menos de
    4 alertas, se devuelve un único cluster 0.

    Devuelve un diccionario ordenado por tamaño de cluster descendente.
    """
    if not alerts:
        return {}

    if len(alerts) < 4:
        return {0: list(alerts)}

    textos = [a.description for a in alerts]

    vectorizador = TfidfVectorizer(
        max_features=500,
        stop_words=["spanish", "english"],
        lowercase=True,
    )
    X = vectorizador.fit_transform(textos)

    max_k = min(max_clusters, len(alerts))
    k = _elbow_k(X, max_k)

    modelo = KMeans(n_clusters=k, random_state=42, n_init=10)
    etiquetas = modelo.fit_predict(X)

    clusters: Dict[int, List[AlertEvent]] = {}
    for alerta, etiqueta in zip(alerts, etiquetas):
        clusters.setdefault(int(etiqueta), []).append(alerta)

    # Ordenar por tamaño descendente y reasignar IDs secuenciales
    ordenados = sorted(clusters.values(), key=len, reverse=True)
    return {i: grupo for i, grupo in enumerate(ordenados)}
