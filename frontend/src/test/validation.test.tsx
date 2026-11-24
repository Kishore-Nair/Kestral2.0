import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import ValidationPanel from "@/components/validation/ValidationPanel";
import ReportDownload from "@/components/validation/ReportDownload";
import type { ValidationApi } from "@/services/validationApi";
import type { ValidationOverview, ValidationRun } from "@/types/validation";

// Test data only: contract-shaped, not output from a real validation.
const RUN: ValidationRun = {
  schema_version: "1.0",
  validation_id: "val_1",
  scan_id: "scan_test",
  status: "completed",
  change: {
    source_type: "remediation", source_id: "rem_1", finding_id: "finding:1", component_id: "cmp:w",
    package: "werkzeug", ecosystem: "pypi", project_path: "examples/celery", from_version: "2.3.3",
    to_version: "3.0.3", approved_by: "Asha", approved_at: "2026-11-24T00:00:00Z",
  },
  error: null,
  created_at: "2026-11-24T00:00:00Z",
  finished_at: "2026-11-24T00:01:00Z",
  result: {
    verdict: "FIXED",
    verdict_reason: "The rescan no longer reports the original vulnerability",
    tests_status: "no_tests",
    tests_detail: "No test suite was found for the changed project",
    sandbox_commit: "a".repeat(40),
    steps: [
      { id: "sandbox", label: "Isolated checkout of the scanned commit", status: "passed", detail: "Fresh clone", duration_ms: 10 },
      { id: "tests", label: "Build and run project tests", status: "warning", detail: "No tests", duration_ms: 10 },
    ],
    diffs: [{ path: "examples/celery/requirements.txt", lines_added: 1, lines_removed: 1, diff: "-werkzeug==2.3.3\n+werkzeug==3.0.3\n", truncated: false }],
    tests: [{ phase: "patched", status: "no_tests", runtime: "podman", image: "python:3.12-slim", command: "pytest", exit_code: 0, duration_s: 12, output_tail: "KESTRAL_NO_TESTS" }],
    comparison: {
      target_resolved: true, target_remaining: [], resolved: [], introduced: [], introduced_suspicious: [],
      before_counts: { critical: 4, high: 30 }, after_counts: { critical: 3, high: 28 },
      package_changes: { upgraded: 1 }, changed_packages: ["werkzeug (examples/celery): 2.3.3 → 3.0.3"],
    },
    rescan_artifacts: "scan_test/validations/val_1",
    residual_risks: ["Not reachability-checked"],
  },
};

function overview(over: Partial<ValidationOverview> = {}): ValidationOverview {
  return {
    schema_version: "1.0",
    scan_id: "scan_test",
    sandbox: { container_runtime: "podman", tests_enabled: true, npm_available: true, notes: [] },
    candidates: [{
      source_type: "remediation", source_id: "rem_1", finding_id: "finding:1", title: "Upgrade werkzeug",
      package: "werkzeug@2.3.3", ecosystem: "pypi", from_version: "2.3.3", to_version: "3.0.3",
      approved_by: "Asha", approved_at: "2026-11-24T00:00:00Z", supported: true, reason: null,
    }],
    runs: [],
    ...over,
  };
}

function fakeClient(over: Partial<ValidationApi> = {}): ValidationApi {
  return {
    overview: vi.fn(async () => overview()),
    start: vi.fn(async () => ({ ...RUN, status: "queued" as const, result: null })),
    get: vi.fn(async () => RUN),
    reportUrl: (scanId, format, download = true) => `http://api/scans/${scanId}/report.${format}${download ? "" : "?download=false"}`,
    ...over,
  };
}

describe("ValidationPanel", () => {
  it("lists approved changes and starts a sandbox validation with tests", async () => {
    const client = fakeClient();
    render(<ValidationPanel scanId="scan_test" client={client} />);
    expect(await screen.findByText(/approved by Asha/)).toBeInTheDocument();
    expect(screen.getByText("Container: podman")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Validate in sandbox/ }));
    await waitFor(() => expect(client.start).toHaveBeenCalledWith("scan_test", "remediation", "rem_1", true));
  });

  it("shows the verdict, diff, before/after and that nothing was pushed", async () => {
    const client = fakeClient({ overview: vi.fn(async () => overview({ runs: [RUN] })) });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    expect(await screen.findByText("Fix verified in sandbox")).toBeInTheDocument();
    expect(screen.getByText("examples/celery/requirements.txt")).toBeInTheDocument();
    expect(screen.getByText(/Target finding no longer detected/)).toBeInTheDocument();
    expect(screen.getByText(/Nothing was merged, pushed or deployed/)).toBeInTheDocument();
  });

  it("explains when there is nothing approved or no container", async () => {
    const client = fakeClient({
      overview: vi.fn(async () => overview({
        candidates: [],
        sandbox: { container_runtime: null, tests_enabled: false, npm_available: true, notes: ["No container runtime"] },
      })),
    });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    expect(await screen.findByText(/No approved changes yet/)).toBeInTheDocument();
    expect(screen.getByRole("checkbox")).toBeDisabled();
  });
});

describe("ReportDownload", () => {
  it("links the HTML and JSON reports", () => {
    render(<ReportDownload scanId="scan_test" client={fakeClient()} />);
    expect(screen.getByRole("link", { name: /Download HTML/ })).toHaveAttribute("href", "http://api/scans/scan_test/report.html");
    expect(screen.getByRole("link", { name: /Download JSON/ })).toHaveAttribute("href", "http://api/scans/scan_test/report.json");
    expect(screen.getByRole("link", { name: /print to PDF/ })).toHaveAttribute("href", "http://api/scans/scan_test/report.html?download=false");
  });

  it("is unavailable in sample data mode", () => {
    render(<ReportDownload scanId="scan_test" client={fakeClient({ reportUrl: () => null })} />);
    expect(screen.getByText(/not available in sample data mode/)).toBeInTheDocument();
  });
});
