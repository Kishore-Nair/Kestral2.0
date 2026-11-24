"""Base model used by every public contract."""

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Reject undeclared fields so producer/consumer drift fails immediately."""

    model_config = ConfigDict(extra="forbid")

