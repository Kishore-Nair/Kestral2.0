package kestral.security

import rego.v1

valid_input if {
	input.schema_version == "1.0"
	is_boolean(input.strict)
	is_boolean(input.findings_partial)
	is_array(input.findings)
	is_array(input.artifacts)
	input.assessment in {"complete", "partial", "not_assessed", "error"}
	every f in input.findings {
		is_string(f.id)
		count(f.id) > 0
		valid_finding_kind(f)
		valid_score(f.score)
		valid_scope(f.scope)
	}
	every a in input.artifacts {
		is_string(a.reference)
		count(a.reference) > 0
		a.signature_status in {"verified", "failed", "unsigned", "not_assessed", "error"}
		a.attestation_status in {"verified", "failed", "not_available", "not_assessed", "error"}
		a.provenance_status in {"verified", "partial", "failed", "not_assessed", "error"}
		a.identity_verified in {true, false, null}
		is_array(a.evidence)
		every d in a.evidence {
			regex.match("^sha256:[a-f0-9]{64}$", d)
		}
	}
}

valid_finding_kind(f) if f.kind in {"vulnerability", "workflow_pin"}

valid_finding_kind(f) if {
	f.kind == "suspicious"
	object.get(f, "risk_level", null) in {"low", "medium", "high", null}
	valid_category(object.get(f, "category", null))
}

valid_category(null)
valid_category(category) if {
	is_string(category)
	trim_space(category) != ""
	count(category) <= 128
}

valid_score(null)
valid_score(score) if {
	is_number(score)
	score >= 0
	score <= 10
}

valid_scope(null)
valid_scope(scope) if is_string(scope)

incomplete_severity := "BLOCK" if input.strict
else := "REVIEW"

violation(id, severity, message, refs) := {
	"policy_id": id, "severity": severity, "message": message, "evidence_refs": refs,
}

artifact_refs(a) := array.concat([a.reference], a.evidence)

violations contains v if {
	some f in input.findings
	f.kind == "vulnerability"
	f.scope == "runtime"
	is_number(f.score)
	f.score >= 9
	v := violation("POL-001", "BLOCK", "Critical runtime vulnerability", [f.id])
}

violations contains v if {
	some a in input.artifacts
	"failed" in {a.signature_status, a.attestation_status, a.provenance_status}
	v := violation("POL-002", "BLOCK", "Signature or provenance verification failed", artifact_refs(a))
}

violations contains v if {
	count(input.artifacts) == 0
	v := violation("POL-003", incomplete_severity, "Required provenance is absent", ["provenance.json"])
}

fully_verified(a) if {
	a.signature_status == "verified"
	a.attestation_status == "verified"
	a.provenance_status == "verified"
	a.identity_verified == true
	a.trust_method in {"configured_public_key", "pinned_certificate_identity"}
	regex.match("^sha256:[a-f0-9]{64}$", a.digest)
	count({d | some d in a.evidence}) >= 3
}

violations contains v if {
	some a in input.artifacts
	not fully_verified(a)
	v := violation("POL-003", incomplete_severity, "Required provenance is incomplete", artifact_refs(a))
}

violations contains v if {
	some a in input.artifacts
	a.identity_verified == false
	v := violation("POL-004", "BLOCK", "Signer is explicitly unauthorized", artifact_refs(a))
}

violations contains v if {
	some f in input.findings
	f.kind == "workflow_pin"
	v := violation("POL-005", "REVIEW", "Workflow reference needs review", [f.id])
}

violations contains v if {
	input.findings_partial
	v := violation("POL-006", incomplete_severity, "Findings evidence is incomplete", ["findings.json"])
}

violations contains v if {
	input.assessment != "complete"
	v := violation("POL-006", incomplete_severity, "Provenance assessment is incomplete", ["provenance.json"])
}

finding_incomplete(f) if f.score == null
finding_incomplete(f) if not f.scope in {"runtime", "dev", "optional"}

violations contains v if {
	some f in input.findings
	f.kind == "vulnerability"
	finding_incomplete(f)
	v := violation("POL-006", incomplete_severity, "Vulnerability score or scope unavailable", [f.id])
}

violations contains v if {
	some f in input.findings
	f.kind == "suspicious"
	f.risk_level == "high"
	v := violation("POL-007", "REVIEW", "High-risk suspicious finding requires review", [f.id])
}

decision := "BLOCK" if {
	some v in violations
	v.severity == "BLOCK"
}
else := "REVIEW" if count(violations) > 0
else := "ALLOW"

result := {"decision": decision, "violations": sort(violations)} if valid_input
