import axios from "axios";
import type { ScanCreate, ScanCreated, ScanState, Inventory } from "@/types/api";
import type { GraphDocument } from "@/types/graph";
import type { DependencyDocument } from "@/types/sbom";
import type { FindingsDocument } from "@/types/findings";
import type { RemediationDecisionCreate, RemediationList, RemediationProposal } from "@/types/remediation";

export interface ScanApi {
  createScan(body: ScanCreate): Promise<ScanCreated>;
  getScan(id: string): Promise<ScanState>;
  getInventory(id: string): Promise<Inventory>;
  getSbom(id: string): Promise<DependencyDocument>;
  getGraph(id: string): Promise<GraphDocument>;
  getFindings(id: string): Promise<FindingsDocument>;
  getRemediations(id: string): Promise<RemediationList>;
  decideRemediation(id: string, proposalId: string, body: RemediationDecisionCreate): Promise<RemediationProposal>;
}

const client = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1",
  timeout: 15_000,
});

export const api: ScanApi = {
  createScan: async (body) =>
    (await client.post<ScanCreated>("/scans", body)).data,
  getScan: async (id) =>
    (await client.get<ScanState>(`/scans/${encodeURIComponent(id)}`)).data,
  getInventory: async (id) =>
    (await client.get<Inventory>(`/scans/${encodeURIComponent(id)}/inventory`)).data,
  getSbom: async (id) =>
    (await client.get<DependencyDocument>(`/scans/${encodeURIComponent(id)}/sbom`)).data,
  getGraph: async (id) =>
    (await client.get<GraphDocument>(`/scans/${encodeURIComponent(id)}/graph`)).data,
  getFindings: async (id) =>
    (await client.get<FindingsDocument>(`/scans/${encodeURIComponent(id)}/findings`)).data,
  getRemediations: async (id) =>
    (await client.get<RemediationList>(`/scans/${encodeURIComponent(id)}/remediations`)).data,
  decideRemediation: async (id, proposalId, body) =>
    (await client.post<RemediationProposal>(
      `/scans/${encodeURIComponent(id)}/remediations/${encodeURIComponent(proposalId)}/decision`, body,
    )).data,
};
