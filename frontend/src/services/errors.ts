import axios from "axios";
import type { ApiError } from "@/types/api";

export type ErrorKind =
  | "not_found" | "not_ready" | "validation" | "busy" | "unavailable" | "network" | "unknown";

export interface FriendlyError {
  kind: ErrorKind;
  status: number | null;
  message: string;
}

function backendMessage(data: unknown): string | null {
  const body = data as Partial<ApiError> | undefined;
  const message = body?.error?.message;
  return typeof message === "string" && message.trim() ? message : null;
}

export function classifyError(error: unknown): FriendlyError {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status ?? null;
    const detail = backendMessage(error.response?.data);
    switch (status) {
      case 404:
        // Kestral 404s carry a structured error; FastAPI's bare {"detail":"Not Found"} means the
        // running backend has no such route (usually an outdated server), not a missing scan.
        if (detail) return { kind: "not_found", status, message: detail };
        if ((error.response?.data as { detail?: unknown } | undefined)?.detail === "Not Found") {
          return { kind: "unavailable", status, message: "The running backend does not provide this endpoint. Restart it from the latest code." };
        }
        return { kind: "not_found", status, message: "Scan ID was not found. Submit the repository again." };
      case 409:
        return { kind: "not_ready", status, message: detail ?? "Not ready yet." };
      case 422:
        return { kind: "validation", status, message: detail ?? "The repository URL or branch/tag was rejected." };
      case 429:
        return { kind: "busy", status, message: "The scanner is busy with another scan. Try again shortly." };
      case 503:
        return { kind: "unavailable", status, message: detail ?? "The scanner service is temporarily unavailable." };
      case null:
        return {
          kind: "network",
          status,
          message: error.code === "ECONNABORTED"
            ? "The request timed out. Check the API and retry."
            : "Could not reach the scanner API. Check that the backend is running.",
        };
      default:
        return { kind: "unknown", status, message: detail ?? `Unexpected response (HTTP ${status}).` };
    }
  }
  return { kind: "unknown", status: null, message: "Something went wrong. Please retry." };
}

export function getFriendlyError(error: unknown): string {
  return classifyError(error).message;
}
