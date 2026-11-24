import { api, type ScanApi } from "@/services/api";
import { mockApi } from "@/services/mockApi";

export const USE_MOCKS = process.env.NEXT_PUBLIC_USE_MOCKS === "true";

export const scanService: ScanApi = USE_MOCKS ? mockApi : api;
