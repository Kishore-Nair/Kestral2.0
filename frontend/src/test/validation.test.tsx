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
    tests_status: "passed",
    tests_detail: "Regression tests passed in the container",
    sandbox_commit: "a".repeat(40),
    steps: [
      { id: "sandbox", label: "Isolated checkout of the scanned commit", status: "passed", detail: "Fresh clone", duration_ms: 10 },
      { id: "tests", label: "Build and run project tests", status: "passed", detail: "Regression tests passed", duration_ms: 10 },
    ],
    diffs: [{ path: "examples/celery/requirements.txt", lines_added: 1, lines_removed: 1, diff: "-werkzeug==2.3.3\n+werkzeug==3.0.3\n", truncated: false }],
    tests: [{ phase: "patched", status: "passed", runtime: "podman", image: "python:3.12-slim", command: "pytest", exit_code: 0, duration_s: 12, output_tail: "3 passed" }],
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
    openPullRequest: vi.fn(async () => ({
      ...RUN,
      pull_request: { url: "https://github.com/o/r/pull/7", number: 7, branch: "kestral/fix-werkzeug-3.0.3-aaaaaa", base: "main", created_at: "2026-11-24T00:02:00Z" },
    })),
    startRuntime: vi.fn(async () => ({ container_runtime: "podman", tests_enabled: true, npm_available: true, notes: [] })),
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

describe("Pull request action", () => {
  const ready = { ...RUN, patch_available: true };

  it("does not offer a PR for a legacy FIXED record without passing tests", async () => {
    const untested = { ...ready, result: { ...RUN.result!, tests_status: "not_run" as const } };
    render(<ValidationPanel scanId="scan_test" client={fakeClient({ overview: vi.fn(async () => overview({ runs: [untested] })) })} />);
    await screen.findByText("Fix verified in sandbox");
    expect(screen.queryByRole("button", { name: /Open pull request/ })).toBeNull();
  });

  it("shows actual completed stages while the validation is still running", async () => {
    const running = { ...RUN, status: "running" as const, result: null, progress: [
      { id: "lockfile", label: "Regenerate the lockfile", status: "passed" as const,
        detail: "Resolved inside the container", duration_ms: 1200 },
    ] };
    const view = render(<ValidationPanel scanId="scan_test" client={fakeClient({ overview: vi.fn(async () => overview({ runs: [running] })) })} />);
    expect(await screen.findByText("Regenerate the lockfile")).toBeInTheDocument();
    expect(screen.getByText("Resolved inside the container")).toBeInTheDocument();
    view.unmount();
  });

  it("opens a pull request for a FIXED validation when GitHub is configured", async () => {
    let runs = [ready];
    const client = fakeClient({
      overview: vi.fn(async () => overview({ runs, sandbox: { container_runtime: "podman", tests_enabled: true, npm_available: true, notes: [], github_configured: true } })),
    });
    (client.openPullRequest as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      runs = [{ ...ready, pull_request: { url: "https://github.com/o/r/pull/7", number: 7, branch: "kestral/fix-werkzeug-3.0.3-aaaaaa", base: "main", created_at: "2026-11-24T00:02:00Z" } }];
      return runs[0];
    });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    fireEvent.click(await screen.findByRole("button", { name: /Open pull request/ }));
    await waitFor(() => expect(client.openPullRequest).toHaveBeenCalledWith("scan_test", "val_1"));
    expect(await screen.findByRole("link", { name: /Pull request #7/ })).toHaveAttribute("href", "https://github.com/o/r/pull/7");
    expect(screen.getByText(/Review and merge it on GitHub/)).toBeInTheDocument();
    expect(screen.getByText(/proposed as a pull request; nothing was merged/)).toBeInTheDocument();
  });

  it("explains the token requirement and hides the button for unfixed runs", async () => {
    const notFixed = { ...ready, validation_id: "val_2", result: { ...RUN.result!, verdict: "NOT_FIXED" as const } };
    const client = fakeClient({ overview: vi.fn(async () => overview({ runs: [ready, notFixed] })) });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    expect(await screen.findByRole("button", { name: /Open pull request/ })).toBeDisabled();
    expect(screen.getByText(/Set GITHUB_TOKEN in .env/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Open pull request/ })).toHaveLength(1);
  });
});

describe("Refreshing approved changes", () => {
  it("reloads when a decision is recorded for this scan, and on Refresh", async () => {
    const { announceDecision } = await import("@/lib/decisionEvents");
    let calls = 0;
    const client = fakeClient({
      overview: vi.fn(async () => {
        calls += 1;
        return overview({ candidates: calls === 1 ? [] : overview().candidates });
      }),
    });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    expect(await screen.findByText(/No approved changes yet/)).toBeInTheDocument();

    announceDecision({ scanId: "another_scan", source: "ai" });
    await new Promise((r) => setTimeout(r, 20));
    expect(client.overview).toHaveBeenCalledTimes(1); // other scans are ignored

    announceDecision({ scanId: "scan_test", source: "remediation" });
    expect(await screen.findByText(/approved by Asha/)).toBeInTheDocument();
    expect(client.overview).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    await waitFor(() => expect(client.overview).toHaveBeenCalledTimes(3));
  });
});

describe("Sandbox panel buttons", () => {
  it("starts Podman when no container runtime is running", async () => {
    let started = false;
    const client = fakeClient({
      overview: vi.fn(async () => overview({
        sandbox: started
          ? { container_runtime: "podman", tests_enabled: true, npm_available: true, notes: [] }
          : { container_runtime: null, tests_enabled: false, npm_available: true, notes: [] },
      })),
      startRuntime: vi.fn(async () => { started = true; return { container_runtime: "podman", tests_enabled: true, npm_available: true, notes: [] }; }),
    });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    fireEvent.click(await screen.findByRole("button", { name: /Start Podman/ }));
    expect(await screen.findByText("Container: podman")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/Podman is running/);
    expect(screen.queryByRole("button", { name: /Start Podman/ })).toBeNull();
  });

  it("guides to approvals from the empty state", async () => {
    const opened: string[] = [];
    window.addEventListener("kestral:open-remediation", () => opened.push("open"));
    render(<ValidationPanel scanId="scan_test" client={fakeClient({ overview: vi.fn(async () => overview({ candidates: [] })) })} />);
    fireEvent.click(await screen.findByRole("button", { name: /Review remediation proposals/ }));
    expect(opened).toEqual(["open"]);
    expect(screen.getByRole("button", { name: /Analyze a finding with AI/ })).toBeInTheDocument();
  });

  it("validates without tests, re-runs, copies the diff and toggles details", async () => {
    const older = { ...RUN, validation_id: "val_0", created_at: "2026-11-23T00:00:00Z" };
    const client = fakeClient({ overview: vi.fn(async () => overview({ runs: [RUN, older] })) });
    const writeText = vi.fn(async () => undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<ValidationPanel scanId="scan_test" client={client} />);

    fireEvent.click(await screen.findByRole("button", { name: /Validate without tests/ }));
    await waitFor(() => expect(client.start).toHaveBeenCalledWith("scan_test", "remediation", "rem_1", false));
    expect(screen.getByText(/Last: Fix verified in sandbox/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Validate again/ })).toBeInTheDocument();

    const reruns = screen.getAllByRole("button", { name: /Re-run/ });
    fireEvent.click(reruns[0]);
    await waitFor(() => expect(client.start).toHaveBeenLastCalledWith("scan_test", "remediation", "rem_1", true));

    fireEvent.click(screen.getAllByRole("button", { name: /Copy diff/ })[0]);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("-werkzeug==2.3.3\n+werkzeug==3.0.3\n"));

    expect(screen.queryByLabelText("Validation val_0")).toBeNull();
    expect(screen.getByText(/Earlier attempts remain available in the audit report/)).toBeInTheDocument();
    const toggles = screen.getAllByRole("button", { name: /details/ });
    expect(toggles).toHaveLength(1);
    expect(toggles[0]).toHaveTextContent("Hide details"); // newest run starts open
    fireEvent.click(toggles[0]);
    expect(screen.getAllByRole("button", { name: /details/ })[0]).toHaveTextContent("Show details");
  });

  it("offers Try again when the scanner is busy", async () => {
    const busyError = Object.assign(new Error("busy"), {
      isAxiosError: true, response: { status: 429, data: { error: { message: "The scanner is busy" } } },
    });
    let attempts = 0;
    const client = fakeClient({
      start: vi.fn(async () => {
        attempts += 1;
        if (attempts === 1) throw busyError;
        return { ...RUN, status: "queued" as const, result: null };
      }),
    });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    fireEvent.click(await screen.findByRole("button", { name: /Validate in sandbox/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Try again/ }));
    await waitFor(() => expect(client.start).toHaveBeenCalledTimes(2));
  });

  it("links the report from the panel header", async () => {
    render(<ValidationPanel scanId="scan_test" client={fakeClient()} />);
    expect(await screen.findByRole("link", { name: /Open report/ })).toHaveAttribute("href", "http://api/scans/scan_test/report.html?download=false");
  });
});

describe("Header play button", () => {
  const second = {
    ...overview().candidates[0], source_id: "rem_2", package: "jinja2@3.1.2", from_version: "3.1.2", to_version: "3.1.6",
  };

  it("validates every approved change one after another", async () => {
    const done: string[] = [];
    const client = fakeClient({
      overview: vi.fn(async () => overview({
        candidates: [overview().candidates[0], second],
        runs: done.map((id, i) => ({ ...RUN, validation_id: `val_${i}`, change: { ...RUN.change, source_id: id } })),
      })),
      start: vi.fn(async (_scan, _type, sourceId: string) => {
        done.push(sourceId); // each run finishes immediately in this fake
        return { ...RUN, status: "queued" as const, result: null };
      }),
    });
    render(<ValidationPanel scanId="scan_test" client={client} />);
    const play = await screen.findByRole("button", { name: "Run sandbox validation" });
    expect(play).toHaveAttribute("title", "Validate 2 approved changes with tests");
    fireEvent.click(play);
    await waitFor(() => expect(client.start).toHaveBeenCalledTimes(2));
    expect(vi.mocked(client.start).mock.calls.map((c) => c[2])).toEqual(["rem_1", "rem_2"]);
  });

  it("is disabled until something approved can be validated", async () => {
    render(<ValidationPanel scanId="scan_test" client={fakeClient({ overview: vi.fn(async () => overview({ candidates: [] })) })} />);
    const play = await screen.findByRole("button", { name: "Run sandbox validation" });
    await waitFor(() => expect(play).toBeDisabled());
    expect(play).toHaveAttribute("title", "Approve a version upgrade first");
  });
});
