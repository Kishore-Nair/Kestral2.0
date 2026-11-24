"""Contract-shaped API errors and FastAPI exception handlers."""

import logging
from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import JsonValue

from app.schemas.error import ErrorDetail, ErrorResponse

logger = logging.getLogger(__name__)


class ApiProblem(Exception):
    def __init__(
        self,
        *,
        status: int,
        code: str,
        message: str,
        scan_id: str | None = None,
        details: Mapping[str, JsonValue] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.scan_id = scan_id
        self.details = dict(details or {})


def _response(problem: ApiProblem) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorDetail(
            code=problem.code,
            message=problem.message,
            details=problem.details,
        ),
        scan_id=problem.scan_id,
    )
    return JSONResponse(status_code=problem.status, content=body.model_dump(mode="json"))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiProblem)
    async def api_problem_handler(_request: Request, exc: ApiProblem) -> JSONResponse:
        return _response(exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        issues: list[JsonValue] = [
            {
                "location": ".".join(str(item) for item in error["loc"]),
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        return _response(
            ApiProblem(
                status=422,
                code="INVALID_REQUEST",
                message="Request validation failed",
                details={"issues": issues},
            )
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled API error", exc_info=exc)
        return _response(
            ApiProblem(
                status=500,
                code="INTERNAL_ERROR",
                message="The service encountered an unexpected error",
            )
        )

