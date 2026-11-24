import { describe, expect, it } from "vitest";
import { classifyError } from "@/services/errors";
import { httpError, networkError } from "@/test/helpers";

describe("classifyError", () => {
  it("maps each API status to a distinct UI message", () => {
    const kinds = [404, 409, 422, 429, 503].map((s) => classifyError(httpError(s)));
    expect(kinds.map((k) => k.kind)).toEqual(["not_found", "not_ready", "validation", "busy", "unavailable"]);
    expect(new Set(kinds.map((k) => k.message)).size).toBe(5);
  });

  it("uses the sanitized backend message for 422", () => {
    const err = httpError(422, { error: { code: "INVALID_URL", message: "Only github.com is allowed", details: {} }, scan_id: null });
    expect(classifyError(err).message).toBe("Only github.com is allowed");
  });

  it("treats network failures as transient, not FAILED", () => {
    expect(classifyError(networkError()).kind).toBe("network");
    expect(classifyError(new Error("boom")).kind).toBe("unknown");
  });
});
