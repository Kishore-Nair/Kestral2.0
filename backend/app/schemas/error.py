"""Stable API error envelope."""

from pydantic import Field, JsonValue

from app.schemas.base import StrictModel


class ErrorDetail(StrictModel):
    code: str
    message: str
    details: dict[str, JsonValue] = Field(default_factory=dict)


class ErrorResponse(StrictModel):
    error: ErrorDetail
    scan_id: str | None = None

