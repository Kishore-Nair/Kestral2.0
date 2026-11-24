import axios from "axios";
import type { SandboxInfo, SourceType, ValidationOverview, ValidationRun } from "@/types/validation";

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

export interface ValidationApi {
  overview(scanId: string): Promise<ValidationOverview>;
  start(scanId: string, sourceType: SourceType, sourceId: string, runTests: boolean): Promise<ValidationRun>;
  get(scanId: string, validationId: string): Promise<ValidationRun>;
  openPullRequest(scanId: string, validationId: string): Promise<ValidationRun>;
  startRuntime(): Promise<SandboxInfo>;
  reportUrl(scanId: string, format: "html" | "json", download?: boolean): string | null;
}

const client = axios.create({ baseURL: API_BASE, timeout: 20_000 });
const enc = encodeURIComponent;

export const validationApi: ValidationApi = {
  overview: async (scanId) => (await client.get<ValidationOverview>(`/scans/${enc(scanId)}/validations`)).data,
  start: async (scanId, sourceType, sourceId, runTests) =>
    (await client.post<ValidationRun>(`/scans/${enc(scanId)}/validations`, {
      source_type: sourceType, source_id: sourceId, run_tests: runTests,
    })).data,
  get: async (scanId, validationId) =>
    (await client.get<ValidationRun>(`/scans/${enc(scanId)}/validations/${enc(validationId)}`)).data,
  openPullRequest: async (scanId, validationId) =>
    (await client.post<ValidationRun>(
      `/scans/${enc(scanId)}/validations/${enc(validationId)}/pull-request`, null, { timeout: 60_000 },
    )).data,
  startRuntime: async () => (await client.post<SandboxInfo>("/sandbox/runtime/start", null, { timeout: 300_000 })).data,
  reportUrl: (scanId, format, download = true) =>
    `${API_BASE}/scans/${enc(scanId)}/report.${format}${download ? "" : "?download=false"}`,
};

/** Sample-data mode never fabricates validations or reports. */
export const mockValidationApi: ValidationApi = {
  overview: async (scanId) => ({
    schema_version: "1.0", scan_id: scanId,
    sandbox: { container_runtime: null, tests_enabled: false, npm_available: false,
      notes: ["Sample data mode: sandbox validation and reports are not available."] },
    candidates: [], runs: [],
  }),
  start: async () => { throw new Error("Sandbox validation is not available in sample data mode"); },
  get: async () => { throw new Error("Sandbox validation is not available in sample data mode"); },
  openPullRequest: async () => { throw new Error("Pull requests are not available in sample data mode"); },
  startRuntime: async () => { throw new Error("The sandbox is not available in sample data mode"); },
  reportUrl: () => null,
};

export const validationService: ValidationApi =
  process.env.NEXT_PUBLIC_USE_MOCKS === "true" ? mockValidationApi : validationApi;
