import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import PrivacyPanel from "@/components/privacy/PrivacyPanel";
import type { PrivacyApi } from "@/services/privacyApi";
import type { DataContext, PrivacyAssessment } from "@/types/privacy";

function makeAssessment(dataContext: DataContext = "simple"): PrivacyAssessment {
  const dpc = { simple: 1, behavioural: 2, financial: 3, sensitive: 4 }[dataContext];
  const score = dpc === 4 ? 5.0 : 2.0;
  const band = dpc === 4 ? "very_high" : "medium";
  return {
    schema_version: "1.0",
    scan_id: "scan_1",
    data_context: dataContext,
    dpc,
    data_contexts: [
      { value: "simple", label: "Simple personal data", dpc: 1, examples: "Names, email addresses" },
      { value: "behavioural", label: "Behavioural data", dpc: 2, examples: "Browsing history" },
      { value: "financial", label: "Financial data", dpc: 3, examples: "Payment cards" },
      { value: "sensitive", label: "Sensitive / special category", dpc: 4, examples: "Health, biometrics" },
    ],
    method: "ENISA SE = DPC × EI + CB",
    dataset: {
      dataset_file: "cve_linddun.parquet",
      dataset_sha256: "abc123",
      dataset_rows: 280_694,
      dataset_labelled_rows: 108_000,
      built_at: "2026-11-24T00:00:00Z",
      cwes: 766,
      cwes_mapped: 342,
      cwes_from_chain: 59,
      label_rule: "CWE → LINDDUN",
    },
    summary: {
      assessed: 2,
      mapped: 1,
      unmapped: 1,
      by_band: { [band]: 1 },
      by_linddun: { Identifiability: 1, "Data Disclosure": 1 },
      unmapped_reasons: { cwe_excluded: 1 },
      max_score: score,
      max_band: band,
    },
    impacts: [
      {
        finding_id: "finding:1",
        title: "Information exposure in logs",
        subject_label: "logger@1.0.0",
        advisory_ids: ["CVE-2024-0001"],
        status: "mapped",
        linddun: ["Identifiability", "Data Disclosure"],
        mappings: [
          {
            cwe_id: "CWE-532",
            status: "mapped",
            linddun: ["Identifiability", "Data Disclosure"],
            inherited: [],
            override: false,
            rationale: "Sensitive data written to log files.",
            mitre_categories: [],
            nvd_cves: 100,
            source: "dataset",
          },
        ],
        score,
        band,
        dpc,
        ei: 1.0,
        cb: 1.0,
        factors: [
          { name: "DPC", value: dpc, basis: `Data context: ${dataContext}` },
          { name: "EI", value: 1.0, basis: "Identifiability" },
          { name: "CB", value: 1.0, basis: "CVSS C:H + remote" },
        ],
        uncertainty: [],
        security_priority: 80,
      },
      {
        finding_id: "finding:2",
        title: "Uncontrolled resource consumption",
        subject_label: "parser@2.0.0",
        advisory_ids: ["CVE-2024-0002"],
        status: "cwe_excluded",
        linddun: [],
        mappings: [
          {
            cwe_id: "CWE-400",
            status: "cwe_excluded",
            linddun: [],
            inherited: [],
            override: false,
            rationale: "DoS-only CWE excluded.",
            mitre_categories: [],
            nvd_cves: 50,
            source: "dataset",
          },
        ],
        score: null,
        band: null,
        dpc,
        ei: null,
        cb: null,
        factors: [],
        uncertainty: [],
        security_priority: 50,
      },
    ],
    caveats: ["ENISA score estimates potential personal-data severity."],
  };
}

describe("PrivacyPanel", () => {
  it("renders ENISA summary, switches data context, and filters by band/unmapped", async () => {
    const client: PrivacyApi = {
      getPrivacy: vi.fn(async (_scanId, ctx) => makeAssessment(ctx ?? "simple")),
    };

    render(<PrivacyPanel scanId="scan_1" client={client} />);
    expect(await screen.findByText(/Worst: 2\.00 \(Medium\)/)).toBeInTheDocument();
    expect(screen.getByText("Information exposure in logs")).toBeInTheDocument();
    expect(screen.getByText("Uncontrolled resource consumption")).toBeInTheDocument();

    // Switch to sensitive data context (DPC = 4) and verify live recomputation.
    fireEvent.click(screen.getByRole("button", { name: /Sensitive \/ special category \(DPC 4\)/ }));
    await waitFor(() => expect(client.getPrivacy).toHaveBeenCalledWith("scan_1", "sensitive"));
    expect(await screen.findByText(/Worst: 5\.00 \(Very high\)/)).toBeInTheDocument();

    // Filter to unmapped findings only.
    fireEvent.click(screen.getByRole("button", { name: "Unmapped (1)" }));
    expect(screen.queryByText("Information exposure in logs")).toBeNull();
    expect(screen.getByText("Uncontrolled resource consumption")).toBeInTheDocument();
  });
});
