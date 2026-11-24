from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

ScanId = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]{1,128}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Reference = Annotated[str, Field(min_length=1, max_length=512)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Artifact(StrictModel):
    artifact_type: Literal["blob"]
    reference: Reference
    digest: Digest | None
    signature_status: Literal["verified", "failed", "unsigned", "not_assessed", "error"]
    attestation_status: Literal["verified", "failed", "not_available", "not_assessed", "error"]
    provenance_status: Literal["verified", "partial", "failed", "not_assessed", "error"]
    identity_verified: bool | None
    trust_method: Literal["configured_public_key", "pinned_certificate_identity"] | None
    evidence: list[Digest] = Field(max_length=8)
    reason: Reference

    @model_validator(mode="after")
    def check_verification(self):
        if self.signature_status == "verified" and (
            self.identity_verified is not True or self.trust_method is None
            or self.digest is None or len(set(self.evidence)) < 2
        ):
            raise ValueError("Verified signature requires digest, trust and evidence")
        if self.provenance_status == "verified" and (
            self.signature_status != "verified" or self.attestation_status != "verified"
            or len(set(self.evidence)) < 3
        ):
            raise ValueError("Verified provenance requires independent attestation evidence")
        return self


class Provenance(StrictModel):
    schema_version: Literal["1.0"]
    scan_id: ScanId
    timestamp: AwareDatetime
    assessment_status: Literal["complete", "partial", "not_assessed", "error"]
    artifacts: list[Artifact] = Field(max_length=256)
    warnings: list[Reference] = Field(max_length=256)
    tool_version: str | None = Field(max_length=80)

    @model_validator(mode="after")
    def check_assessment(self):
        if not self.artifacts and self.assessment_status != "not_assessed":
            raise ValueError("Empty assessment must be marked not_assessed")
        return self
