"""Start, run, cache and read AI analyses. Never touches scan status or scan artifacts."""

import hashlib
import logging
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.agent import AgentLimits, run_agent
from app.ai.bundle import BundleError, ScanBundle
from app.ai.provider import (
    AnthropicProvider,
    GrokProvider,
    GroqProvider,
    Provider,
    ProviderError,
)
from app.ai.tools import ToolContext
from app.config import Settings
from app.database.models import AiAnalysisRow, Scan
from app.schemas.ai import PROMPT_VERSION, AiAnalysis, AiDecision, AiRecommendation, AiStatus

logger = logging.getLogger(__name__)
TERMINAL_OK = {
    "recommendation_ready",
    "needs_human_review",
    "insufficient_evidence",
    "no_verified_fix",
}
ACTIVE = {"queued", "running"}
DATA_NOTICE = (
    "Analyzing a finding sends that finding, its package, dependency paths, saved advisory "
    "records and short evidence excerpts from this scan to the configured AI provider. "
    "Source code, .env files and credentials are never sent. Provider API usage is billed "
    "by the provider separately from any chat subscription."
)
_lock = threading.Lock()


KEY_ENV = {"groq": "GROQ_API_KEY", "xai": "XAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
PROVIDERS = {"groq": GroqProvider, "xai": GrokProvider, "anthropic": AnthropicProvider}
# Provider defaults. Groq's free tier allows ~8K tokens per minute, so its requests stay small.
DEFAULT_MODEL = {"groq": "openai/gpt-oss-120b", "xai": "grok-4.7", "anthropic": "claude-opus-5-5"}
DEFAULT_MAX_OUTPUT = {"groq": 4000, "xai": 16000, "anthropic": 16000}
DEFAULT_RESULT_CHARS = {"groq": 3000, "xai": 12000, "anthropic": 12000}
DEFAULT_EFFORT = {"groq": "low"}  # fewer reasoning tokens against Groq's per-minute limit


def _api_key(settings: Settings):
    return {
        "groq": settings.groq_api_key,
        "xai": settings.xai_api_key,
        "anthropic": settings.anthropic_api_key,
    }.get(settings.ai_provider)


def effort(settings: Settings) -> str | None:
    return settings.ai_effort or DEFAULT_EFFORT.get(settings.ai_provider)


def model_name(settings: Settings) -> str:
    return settings.ai_model or DEFAULT_MODEL.get(settings.ai_provider, "unknown")


def ai_status(settings: Settings) -> AiStatus:
    return AiStatus(
        enabled=settings.ai_enabled,
        configured=bool(settings.ai_enabled and _api_key(settings)),
        provider=settings.ai_provider,
        api_key_env=KEY_ENV.get(settings.ai_provider, "unsupported provider"),
        model=model_name(settings),
        prompt_version=PROMPT_VERSION,
        tool_budget=settings.ai_tool_budget,
        data_notice=DATA_NOTICE,
    )


def build_provider(settings: Settings) -> Provider:
    if not settings.ai_enabled:
        raise ProviderError("not_configured", "AI analysis is disabled (AI_ENABLED is false)")
    if settings.ai_provider not in KEY_ENV:
        raise ProviderError("not_configured", f"Unsupported AI provider {settings.ai_provider!r}")
    key = _api_key(settings)
    if not key:
        raise ProviderError("not_configured", f"{KEY_ENV[settings.ai_provider]} is not set")
    return PROVIDERS[settings.ai_provider](
        api_key=key.get_secret_value(),
        model=model_name(settings),
        effort=effort(settings),
        timeout=settings.ai_timeout_seconds,
        max_tokens=settings.ai_max_output_tokens
        or DEFAULT_MAX_OUTPUT.get(settings.ai_provider, 16000),
    )


def scan_dir(settings: Settings, row: Scan) -> Path:
    return settings.scan_output_root / row.scan_id


def load_bundle(settings: Settings, row: Scan) -> ScanBundle:
    return ScanBundle.load(
        scan_dir(settings, row),
        scan_id=row.scan_id,
        commit_sha=row.commit_sha,
        repository_url=row.repository_url,
        resolved_ref=row.resolved_ref,
        app_name=row.repository_name,
    )


def cache_key(
    row: Scan, finding_id: str, digest: str, provider: str, model: str, effort: str | None
) -> str:
    parts = [
        row.scan_id,
        row.commit_sha or "",
        finding_id,
        digest,
        PROMPT_VERSION,
        provider,
        model,
        effort or "",
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def to_api(row: AiAnalysisRow, current_key: str | None, cached: bool = False) -> AiAnalysis:
    recommendation = AiRecommendation.model_validate(row.result_json) if row.result_json else None
    decision = (
        AiDecision(decision=row.decision, note=row.decision_note, decided_at=row.decided_at)
        if row.decision and row.decided_at
        else None
    )
    return AiAnalysis(
        analysis_id=row.analysis_id,
        scan_id=row.scan_id,
        finding_id=row.finding_id,
        status=row.status,
        stale=current_key is not None and current_key != row.cache_key,
        cached=cached,
        error=row.error_message,
        created_at=row.created_at,
        finished_at=row.finished_at,
        recommendation=recommendation,
        decision=decision,
    )


def latest_for_finding(db: Session, scan_id: str, finding_id: str) -> AiAnalysisRow | None:
    return db.scalars(
        select(AiAnalysisRow)
        .where(AiAnalysisRow.scan_id == scan_id, AiAnalysisRow.finding_id == finding_id)
        .order_by(AiAnalysisRow.created_at.desc())
        .limit(1)
    ).first()


def start_analysis(
    db: Session, settings: Settings, row: Scan, finding_id: str, *, force: bool = False
) -> tuple[AiAnalysisRow, bool]:
    """(analysis row, should_run). Reuses a cached or in-flight analysis with the same key."""
    bundle = load_bundle(settings, row)
    if bundle.finding(finding_id) is None:
        raise KeyError(finding_id)
    key = cache_key(
        row,
        finding_id,
        bundle.digest,
        settings.ai_provider,
        model_name(settings),
        effort(settings),
    )
    with _lock:
        existing = db.scalars(
            select(AiAnalysisRow)
            .where(AiAnalysisRow.cache_key == key)
            .order_by(AiAnalysisRow.created_at.desc())
            .limit(1)
        ).first()
        if existing and (
            existing.status in ACTIVE or (existing.status in TERMINAL_OK and not force)
        ):
            return existing, False
        analysis = AiAnalysisRow(
            analysis_id=f"ai_{uuid.uuid4().hex}",
            scan_id=row.scan_id,
            finding_id=finding_id,
            commit_sha=row.commit_sha,
            cache_key=key,
            status="queued",
            provider=settings.ai_provider,
            model=model_name(settings),
            prompt_version=PROMPT_VERSION,
        )
        db.add(analysis)
        db.commit()
        return analysis, True


def run_analysis(
    session_factory: Callable[[], Session],
    settings: Settings,
    analysis_id: str,
    *,
    provider_factory: Callable[[Settings], Provider] | None = None,
    tool_context: Callable | None = None,
) -> None:
    with session_factory() as db:
        analysis = db.get(AiAnalysisRow, analysis_id)
        if analysis is None:
            return
        scan = db.get(Scan, analysis.scan_id)
        analysis.status = "running"
        db.commit()
        try:
            if scan is None:
                raise BundleError("Scan no longer exists")
            bundle = load_bundle(settings, scan)
            finding = bundle.finding(analysis.finding_id)
            if finding is None:
                raise BundleError("Finding no longer exists in this scan")
            provider = (provider_factory or build_provider)(settings)
            limits = AgentLimits(
                tool_budget=settings.ai_tool_budget,
                external_budget=settings.ai_external_budget,
                wall_clock_seconds=settings.ai_wall_clock_seconds,
                max_result_chars=settings.ai_max_tool_result_chars
                or DEFAULT_RESULT_CHARS.get(settings.ai_provider, 12000),
            )

            def default_context(b, f, store):
                return ToolContext(
                    b, f, store, external_timeout=settings.ai_external_timeout_seconds
                )

            result = run_agent(
                bundle, finding, provider, limits, tool_context=tool_context or default_context
            )
            analysis.status = result.status
            analysis.error_message = result.error
            analysis.result_json = (
                result.recommendation.model_dump(mode="json") if result.recommendation else None
            )
        except ProviderError as exc:
            analysis.status = "ai_unavailable" if exc.kind == "not_configured" else "failed"
            analysis.error_message = str(exc)
        except BundleError as exc:
            analysis.status = "failed"
            analysis.error_message = str(exc)
        except Exception:
            logger.exception("AI analysis failed: analysis_id=%s", analysis_id)
            analysis.status = "failed"
            analysis.error_message = "The analysis failed unexpectedly"
        analysis.finished_at = datetime.now(UTC)
        db.commit()


def current_key(settings: Settings, row: Scan, analysis: AiAnalysisRow) -> str | None:
    try:
        bundle = load_bundle(settings, row)
    except BundleError:
        return None
    return cache_key(
        row,
        analysis.finding_id,
        bundle.digest,
        settings.ai_provider,
        model_name(settings),
        effort(settings),
    )


def record_decision(db: Session, analysis: AiAnalysisRow, decision: str, note: str | None) -> None:
    analysis.decision = decision
    analysis.decision_note = note
    analysis.decided_at = datetime.now(UTC)
    db.commit()
