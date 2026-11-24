import axios from "axios";
import type { AiAnalysis, AiDecisionRequest, AiStatus } from "@/types/ai";

export interface AiApi {
  getStatus(): Promise<AiStatus>;
  getRemediation(scanId: string, findingId: string): Promise<AiAnalysis | null>;
  start(scanId: string, findingId: string, refresh?: boolean): Promise<AiAnalysis>;
  get(scanId: string, analysisId: string): Promise<AiAnalysis>;
  decide(scanId: string, analysisId: string, body: AiDecisionRequest): Promise<AiAnalysis>;
  revise(scanId: string, analysisId: string): Promise<AiAnalysis>;
}

const client = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1",
  timeout: 15_000,
});
const enc = encodeURIComponent;

export const aiApi: AiApi = {
  getStatus: async () => (await client.get<AiStatus>("/ai/status")).data,
  getRemediation: async (scanId, findingId) =>
    (await client.get<AiAnalysis | null>(`/scans/${enc(scanId)}/findings/${enc(findingId)}/remediation`)).data,
  start: async (scanId, findingId, refresh = false) =>
    (await client.post<AiAnalysis>(
      `/scans/${enc(scanId)}/findings/${enc(findingId)}/ai-analysis`, null, { params: refresh ? { refresh: true } : {} },
    )).data,
  get: async (scanId, analysisId) =>
    (await client.get<AiAnalysis>(`/scans/${enc(scanId)}/ai-analysis/${enc(analysisId)}`)).data,
  decide: async (scanId, analysisId, body) =>
    (await client.post<AiAnalysis>(`/scans/${enc(scanId)}/ai-analysis/${enc(analysisId)}/decision`, body)).data,
  revise: async (scanId, analysisId) =>
    (await client.post<AiAnalysis>(`/scans/${enc(scanId)}/ai-analysis/${enc(analysisId)}/revise`)).data,
};

/** Mock mode never fabricates an AI analysis: it reports AI as not configured. */
export const mockAiApi: AiApi = {
  getStatus: async () => ({
    enabled: false, configured: false, provider: "groq", api_key_env: "GROQ_API_KEY", model: "openai/gpt-oss-120b",
    prompt_version: "1.0", tool_budget: 5,
    data_notice: "Sample data mode: AI analysis is not available.",
  }),
  getRemediation: async () => null,
  start: async () => { throw new Error("AI analysis is not available in sample data mode"); },
  get: async () => { throw new Error("AI analysis is not available in sample data mode"); },
  decide: async () => { throw new Error("AI analysis is not available in sample data mode"); },
  revise: async () => { throw new Error("AI analysis is not available in sample data mode"); },
};

export const aiService: AiApi = process.env.NEXT_PUBLIC_USE_MOCKS === "true" ? mockAiApi : aiApi;
