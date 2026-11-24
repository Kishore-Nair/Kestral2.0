import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import RepositoryForm, { buildScanRequest, validateScanInput } from "@/components/scan/RepositoryForm";
import type { ScanApi } from "@/services/api";
import { httpError } from "@/test/helpers";

function makeService(createScan: ScanApi["createScan"]): ScanApi {
  return {
    createScan,
    getScan: vi.fn(), getInventory: vi.fn(), getSbom: vi.fn(), getGraph: vi.fn(),
  };
}

function fill(url: string, ref = "") {
  fireEvent.change(screen.getByLabelText(/GitHub repository URL/i), { target: { value: url } });
  fireEvent.change(screen.getByLabelText(/Branch\/tag/i), { target: { value: ref } });
}

describe("RepositoryForm", () => {
  it("shows an accessible error for an invalid URL and does not submit", async () => {
    const createScan = vi.fn();
    render(<RepositoryForm onSubmitted={vi.fn()} service={makeService(createScan)} />);
    fill("http://gitlab.com/owner/repo");
    fireEvent.click(screen.getByRole("button", { name: /scan repository/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/public GitHub URL/);
    expect(screen.getByLabelText(/GitHub repository URL/i)).toHaveAttribute("aria-invalid", "true");
    expect(createScan).not.toHaveBeenCalled();
  });

  it("submits a typed ScanCreate with blank ref serialized as null", async () => {
    const createScan = vi.fn().mockResolvedValue({ scan_id: "scan_1", status: "QUEUED", repository_name: "repo" });
    const onSubmitted = vi.fn();
    render(<RepositoryForm onSubmitted={onSubmitted} service={makeService(createScan)} />);
    fill("  https://github.com/owner/repo  ", "   ");
    fireEvent.click(screen.getByRole("button", { name: /scan repository/i }));
    await waitFor(() => expect(onSubmitted).toHaveBeenCalled());
    expect(createScan).toHaveBeenCalledWith({ repository_url: "https://github.com/owner/repo", ref: null });
  });

  it("preserves a valid ref and accepts .git suffix", () => {
    expect(buildScanRequest("https://github.com/owner/repo.git", "main"))
      .toEqual({ repository_url: "https://github.com/owner/repo.git", ref: "main" });
    expect(validateScanInput("https://github.com/owner/repo.git", "main")).toBeNull();
    expect(validateScanInput("https://github.com/owner/repo", "--upload-pack=x")).not.toBeNull();
    expect(validateScanInput("https://github.com/owner/repo?x=1", "")).not.toBeNull();
  });

  it("shows the backend 422 message at the input without retrying", async () => {
    const createScan = vi.fn().mockRejectedValue(
      httpError(422, { error: { code: "INVALID_REF", message: "Ref not found", details: {} }, scan_id: null }),
    );
    render(<RepositoryForm onSubmitted={vi.fn()} service={makeService(createScan)} />);
    fill("https://github.com/owner/repo", "nope");
    fireEvent.submit(screen.getByRole("button", { name: /scan repository/i }).closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("Ref not found");
    expect(createScan).toHaveBeenCalledTimes(1);
  });
});
