#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Punto de entrada CLI de AlertMind.

Orquesta la carga de configuración, obtención de alertas desde Wazuh o mock,
clusterización, consulta al LLM local, generación de resúmenes y renderizado.
Autor: Javier Garrido Ortiz
"""

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console

from config_loader import load_config
from alert_fetcher import fetch_alerts
from clusterer import cluster_alerts
from llm_client import query_llm
from summarizer import build_summary
from report import render

console = Console()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Define y parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog="alertmind",
        description="Resume y triagea alertas de Wazuh con un LLM local.",
    )
    parser.add_argument(
        "--source",
        choices=["mock", "wazuh"],
        default="mock",
        help="Origen de las alertas (por defecto: mock).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="mistral",
        help="Nombre del modelo Ollama a usar (por defecto: mistral).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Máximo de alertas por cluster a incluir en el prompt (por defecto: 10).",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Formato de salida (por defecto: table).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Ruta al fichero de configuración (por defecto: config.yaml).",
    )
    parser.add_argument(
        "--lookback",
        type=int,
        default=60,
        help="Minutos hacia atrás para consultar alertas (por defecto: 60).",
    )
    parser.add_argument(
        "--min-level",
        type=int,
        default=7,
        choices=range(1, 16),
        metavar="[1-15]",
        help="Nivel mínimo de alerta Wazuh (por defecto: 7).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Ejecuta el flujo completo de AlertMind."""
    args = parse_args(argv)

    # 1. Cargar configuración
    try:
        config = load_config(args.config)
    except Exception as exc:
        console.print(f"[red]Error cargando configuración: {exc}[/red]")
        return 1

    # 2. Obtener alertas
    try:
        alerts = fetch_alerts(
            source=args.source,
            config=config,
            lookback_minutes=args.lookback,
            min_level=args.min_level,
        )
    except Exception as exc:
        console.print(f"[red]Error obteniendo alertas: {exc}[/red]")
        return 1

    if not alerts:
        console.print("[yellow]No se han obtenido alertas con los filtros actuales.[/yellow]")
        return 0

    console.print(f"[cyan]Alertas obtenidas: {len(alerts)}[/cyan]")

    # 3. Clusterizar alertas
    try:
        clusters = cluster_alerts(alerts)
    except Exception as exc:
        console.print(f"[red]Error en la clusterización: {exc}[/red]")
        return 1

    console.print(f"[cyan]Clusters formados: {len(clusters)}[/cyan]")

    # 4. Consultar LLM y construir resúmenes
    summaries = []
    total_tokens = 0
    start_llm = time.perf_counter()

    for cluster_id, cluster_alerts_list in clusters.items():
        console.print(f"[dim]Procesando cluster {cluster_id} ({len(cluster_alerts_list)} alertas)...[/dim]")
        try:
            llm_response = query_llm(
                cluster_id=cluster_id,
                alerts=cluster_alerts_list,
                model=args.model,
                top=args.top,
                config=config,
            )
            total_tokens += llm_response.get("tokens", 0)
            summary = build_summary(
                cluster_id=cluster_id,
                raw_response=llm_response.get("response", ""),
                alerts=cluster_alerts_list,
            )
            summaries.append(summary)
        except Exception as exc:
            console.print(f"[red]Error procesando cluster {cluster_id}: {exc}[/red]")
            continue

    llm_latency = time.perf_counter() - start_llm

    # 5. Renderizar salida
    try:
        render(summaries, output_format=args.format)
    except Exception as exc:
        console.print(f"[red]Error renderizando resultados: {exc}[/red]")
        return 1

    # Estadísticas finales
    console.print("")
    console.print("[bold]Estadísticas[/bold]")
    console.print(f"  Total alertas: {len(alerts)}")
    console.print(f"  Clusters: {len(clusters)}")
    console.print(f"  Tokens usados: {total_tokens}")
    console.print(f"  Latencia LLM: {llm_latency:.2f} s")

    return 0


if __name__ == "__main__":
    sys.exit(main())