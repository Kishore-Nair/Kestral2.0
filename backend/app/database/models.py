"""Database tables for scan lifecycle metadata."""

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    repository_url: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(150), nullable=False)
    repository_name: Mapped[str] = mapped_column(String(150), nullable=False)
    requested_ref: Mapped[str | None] = mapped_column(String(150))
    resolved_ref: Mapped[str | None] = mapped_column(String(150))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    current_stage: Mapped[str | None] = mapped_column(String(40))
    inventory_path: Mapped[str | None] = mapped_column(Text)
    sbom_path: Mapped[str | None] = mapped_column(Text)
    normalized_path: Mapped[str | None] = mapped_column(Text)
    graph_path: Mapped[str | None] = mapped_column(Text)
    findings_path: Mapped[str | None] = mapped_column(Text)
    warnings_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

