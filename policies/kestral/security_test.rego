package kestral.security

import rego.v1

# Synthetic evidence. These hashes do not correspond to verified artifacts.
hashes := [
	"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
]

artifact := {
	"reference": "synthetic-blob", "digest": hashes[0], "evidence": hashes,
	"signature_status": "verified", "attestation_status": "verified",
	"provenance_status": "verified", "identity_verified": true,
	"trust_method": "configured_public_key",
}

clean := {
	"schema_version": "1.0", "strict": false, "findings_partial": false,
	"findings": [], "assessment": "complete", "artifacts": [artifact],
}

critical := {"id": "synthetic-vuln", "kind": "vulnerability", "scope": "runtime", "score": 9}
mutable := {"id": "synthetic-pin", "kind": "workflow_pin", "scope": null, "score": null}

test_clean_complete if {
	result == {"decision": "ALLOW", "violations": []} with input as clean
}

test_critical_runtime_precedes_review if {
	assessed := result with input as object.union(clean, {"findings": [critical, mutable]})
	assessed.decision == "BLOCK"
	{v.policy_id | some v in assessed.violations} == {"POL-001", "POL-005"}
}

test_failed_signature if {
	failed := object.union(artifact, {"signature_status": "failed", "identity_verified": null})
	assessed := result with input as object.union(clean, {"artifacts": [failed]})
	assessed.decision == "BLOCK"
	some v in assessed.violations
	v.policy_id == "POL-002"
}

test_missing_and_strict if {
	missing := object.union(clean, {"artifacts": [], "assessment": "not_assessed"})
	result.decision == "REVIEW" with input as missing
	result.decision == "BLOCK" with input as object.union(missing, {"strict": true})
}

test_mutable_action if {
	assessed := result with input as object.union(clean, {"findings": [mutable]})
	assessed.decision == "REVIEW"
	[v] := assessed.violations
	v.policy_id == "POL-005"
}

test_partial_and_missing_score if {
	unscored := object.union(critical, {"score": null})
	assessed := result with input as object.union(clean, {
		"findings_partial": true, "findings": [unscored],
	})
	assessed.decision == "REVIEW"
	count(assessed.violations) == 2
	every v in assessed.violations {
		v.policy_id == "POL-006"
	}
}

test_unauthorized_signer if {
	untrusted := object.union(artifact, {"identity_verified": false})
	assessed := result with input as object.union(clean, {"artifacts": [untrusted]})
	assessed.decision == "BLOCK"
	some v in assessed.violations
	v.policy_id == "POL-004"
}

suspicious := {
	"id": "synthetic-suspicious", "kind": "suspicious", "scope": "dev",
	"score": null, "risk_level": "high", "category": "lifecycle_script_indicator",
}

test_suspicious_high_risk_stays_review_in_strict_mode if {
	assessed := result with input as object.union(clean, {"findings": [suspicious], "strict": true})
	assessed.decision == "REVIEW"
	[v] := assessed.violations
	v.policy_id == "POL-007"
	v.evidence_refs == ["synthetic-suspicious"]
}

test_mixed_finding_precedence if {
	assessed := result with input as object.union(clean, {"findings": [suspicious, mutable, critical]})
	assessed.decision == "BLOCK"
	{v.policy_id | some v in assessed.violations} == {"POL-001", "POL-005", "POL-007"}
}

test_low_risk_heuristic_remains_non_blocking if {
	low := object.union(suspicious, {"category": "recent_package", "risk_level": "low"})
	result.decision == "ALLOW" with input as object.union(clean, {"findings": [low]})
}

test_invalid_suspicious_fields_fail_closed if {
	malformed := object.union(suspicious, {"risk_level": "critical"})
	not result with input as object.union(clean, {"findings": [malformed]})
	invalid_category := object.union(suspicious, {"category": []})
	not result with input as object.union(clean, {"findings": [invalid_category]})
}

test_malformed_and_empty_are_undefined if {
	not result with input as {}
	not result with input as object.remove(clean, ["artifacts"])
	not result with input as object.union(clean, {"findings": [{"kind": "vulnerability"}]})
	not result with input as object.union(clean, {"artifacts": [{}]})
}
