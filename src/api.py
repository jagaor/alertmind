import asyncio
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from src.alert_fetcher import fetch_alerts
from src.alert_parser import parse_alerts
from src.clusterer import cluster_alerts
from src.llm_client import generate_summaries
from src.summarizer import SummaryResult
from src.config_loader import load_config

logger = logging.getLogger(__name__)

config: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global config
    config = load_config()
    logger.info("Configuración cargada correctamente")
    yield


app = FastAPI(
    title="AlertMind API",
    description="Resume y triage de alertas de Wazuh con LLM local",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _check_ollama_reachable(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


@app.get("/health")
async def health() -> dict:
    ollama_url = config.get("ollama_url", "http://localhost:11434")
    model = config.get("ollama_model", "llama3")
    reachable = await _check_ollama_reachable(ollama_url)
    return {"status": "ok", "model": model, "ollama_reachable": reachable}


@app.get("/summary", response_model=List[SummaryResult])
async def summary(
    source: str = Query("mock", pattern="^(mock|wazuh)$"),
    model: Optional[str] = Query(None),
    lookback: Optional[int] = Query(None, ge=1),
    min_level: Optional[int] = Query(None, ge=0, le=15),
) -> List[SummaryResult]:
    try:
        effective_model = model or config.get("ollama_model", "llama3")
        effective_lookback = lookback or config.get("lookback_minutes", 60)
        effective_min_level = min_level if min_level is not None else config.get("min_level", 5)

        raw_alerts = await asyncio.to_thread(
            fetch_alerts,
            source=source,
            lookback_minutes=effective_lookback,
            min_level=effective_min_level,
            config=config,
        )
        if not raw_alerts:
            return []

        alerts = parse_alerts(raw_alerts)
        clusters = cluster_alerts(alerts)
        summaries = await asyncio.to_thread(
            generate_summaries,
            clusters=clusters,
            model=effective_model,
            ollama_url=config.get("ollama_url", "http://localhost:11434"),
        )
        return summaries
    except Exception as exc:
        logger.exception("Error procesando /summary")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
