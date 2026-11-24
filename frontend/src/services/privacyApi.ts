import axios from "axios";
import type { DataContext, PrivacyAssessment } from "@/types/privacy";

export interface PrivacyApi {
  getPrivacy(scanId: string, dataContext?: DataContext): Promise<PrivacyAssessment>;
}

const client = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1",
  timeout: 15_000,
});

export const privacyApi: PrivacyApi = {
  getPrivacy: async (scanId, dataContext) =>
    (
      await client.get<PrivacyAssessment>(`/scans/${encodeURIComponent(scanId)}/privacy`, {
        params: dataContext ? { data_context: dataContext } : {},
      })
    ).data,
};

const DPC_BY_CONTEXT: Record<DataContext, number> = {
  simple: 1,
  behavioural: 2,
  financial: 3,
  sensitive: 4,
};

export const mockPrivacyApi: PrivacyApi = {
  getPrivacy: async (scanId, dataContext = "simple") => {
    const dpc = DPC_BY_CONTEXT[dataContext];
    const score = Math.min(6, dpc * 1 + 0.5);
    const band = score >= 4 ? "very_high" : score >= 3 ? "high" : score >= 2 ? "medium" : "low";
    return {
      schema_version: "1.0",
      scan_id: scanId,
      data_context: dataContext,
      dpc,
      data_contexts: [
        { value: "simple", label: "Simple personal data", dpc: 1, examples: "Names, email addresses, basic profile" },
        { value: "behavioural", label: "Behavioural data", dpc: 2, examples: "Browsing history, location, preferences" },
        { value: "financial", label: "Financial data", dpc: 3, examples: "Payment cards, bank accounts, invoices" },
        { value: "sensitive", label: "Sensitive / special category", dpc: 4, examples: "Health, biometrics, credentials, auth tokens" },
      ],
      method: "ENISA personal data breach severity (SE = DPC × EI + CB) with CVE→LINDDUN threat mapping",
      dataset: {
        dataset_file: "cve_linddun.parquet",
        dataset_sha256: "sample",
        dataset_rows: 280_694,
        dataset_labelled_rows: 108_000,
        built_at: "2026-11-24T00:00:00Z",
        cwes: 766,
        cwes_mapped: 342,
        cwes_from_chain: 59,
        label_rule: "CWE → LINDDUN direct or chain mapping",
      },
      summary: {
        assessed: 1,
        mapped: 1,
        unmapped: 0,
        by_band: { [band]: 1 },
        by_linddun: { "Data Disclosure": 1 },
        unmapped_reasons: {},
        max_score: score,
        max_band: band,
      },
      impacts: [
        {
          finding_id: "finding:sample",
          title: "Sample information exposure",
          subject_label: "sample-package@1.0.0",
          advisory_ids: ["GHSA-sample"],
          status: "mapped",
          linddun: ["Data Disclosure"],
          mappings: [
            {
              cwe_id: "CWE-200",
              status: "mapped",
              linddun: ["Data Disclosure"],
              inherited: [],
              override: false,
              rationale: "Sample data fixture.",
              mitre_categories: [],
              nvd_cves: 1,
              source: "sample",
            },
          ],
          score,
          band,
          dpc,
          ei: 1.0,
          cb: 0.5,
          factors: [
            { name: "DPC", value: dpc, basis: `Selected data context: ${dataContext}` },
            { name: "EI", value: 1.0, basis: "Data Disclosure ease of identification" },
            { name: "CB", value: 0.5, basis: "CVSS confidentiality impact" },
          ],
          uncertainty: [],
          security_priority: 70,
        },
      ],
      caveats: ["Sample data mode: values are synthetic fixtures."],
    };
  },
};

export const privacyService: PrivacyApi =
  process.env.NEXT_PUBLIC_USE_MOCKS === "true" ? mockPrivacyApi : privacyApi;
