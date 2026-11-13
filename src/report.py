import json
import os
from datetime import datetime
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.summarizer import SummaryResult


def _severity_color(severity: str) -> str:
    """Devuelve el color asociado a la severidad para Rich."""
    mapping = {
        "CRÍTICO": "red",
        "ALTO": "orange1",
        "MEDIO": "yellow",
        "BAJO": "green",
    }
    return mapping.get(severity.upper(), "white")


def render(summaries: List[SummaryResult], fmt: str, output_dir: str = "output") -> None:
    """Renderiza los resúmenes en formato tabla (Rich) o JSON.

    Args:
        summaries: Lista de SummaryResult a mostrar.
        fmt: Formato de salida, 'table' o 'json'.
        output_dir: Directorio donde se guardará el JSON (solo para fmt='json').
    """
    if fmt == "table":
        console = Console()
        for s in summaries:
            color = _severity_color(s.severity)
            body = Text()
            body.append(f"Severidad: {s.severity}\n", style=f"bold {color}")
            body.append("Resumen:\n", style="bold")
            body.append(f"{s.resumen}\n\n")
            body.append("Próximo paso:\n", style="bold")
            body.append(f"{s.next_step}\n\n")
            if s.mitre_tactics:
                body.append("Tácticas MITRE:\n", style="bold")
                body.append(", ".join(s.mitre_tactics) + "\n")
            panel = Panel(
                body,
                title=f"Cluster {s.cluster_id}",
                border_style=color,
                expand=False,
            )
            console.print(panel)

        # Estadísticas agregadas al pie
        total_alertas = sum(s.alert_count for s in summaries if hasattr(s, "alert_count"))
        total_clusters = len(summaries)
        total_tokens = sum(s.tokens_used for s in summaries if hasattr(s, "tokens_used"))
        total_latencia = sum(s.latency_ms for s in summaries if hasattr(s, "latency_ms"))

        stats_table = Table(title="Estadísticas agregadas", show_header=True, header_style="bold cyan")
        stats_table.add_column("Métrica")
        stats_table.add_column("Valor", justify="right")
        stats_table.add_row("Total alertas", str(total_alertas))
        stats_table.add_row("Clusters", str(total_clusters))
        stats_table.add_row("Tokens totales", str(total_tokens))
        stats_table.add_row("Latencia total (ms)", str(total_latencia))
        console.print(stats_table)

    elif fmt == "json":
        data = [s.model_dump() for s in summaries]
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        print(json_str)

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"alertmind_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_str)
    else:
        raise ValueError(f"Formato no soportado: {fmt}. Use 'table' o 'json'.")
