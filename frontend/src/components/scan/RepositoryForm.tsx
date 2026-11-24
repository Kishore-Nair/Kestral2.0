"use client";

import { useId, useState, type FormEvent } from "react";
import { GitBranch, Loader2, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ScanCreate, ScanCreated } from "@/types/api";
import type { ScanApi } from "@/services/api";
import { scanService as defaultService } from "@/services/scanService";
import { getFriendlyError } from "@/services/errors";

// Usability check only; the backend repeats strict URL validation.
export const GITHUB_URL_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+(?:\.git)?$/;
// Matches backend ScanCreate.ref max_length.
const MAX_REF_LENGTH = 120;

export function buildScanRequest(repositoryUrl: string, ref: string): ScanCreate {
  return { repository_url: repositoryUrl.trim(), ref: ref.trim() || null };
}

export function validateScanInput(repositoryUrl: string, ref: string): string | null {
  if (!GITHUB_URL_PATTERN.test(repositoryUrl.trim())) {
    return "Enter a public GitHub URL such as https://github.com/owner/repo";
  }
  const trimmedRef = ref.trim();
  if (trimmedRef.length > MAX_REF_LENGTH) return "Branch/tag name is too long.";
  if (/\s/.test(trimmedRef) || trimmedRef.startsWith("-")) {
    return "Branch/tag must be a plain name such as main or v1.2.0.";
  }
  return null;
}

interface Props {
  onSubmitted: (created: ScanCreated) => void;
  busy?: boolean;
  service?: ScanApi;
}

export default function RepositoryForm({ onSubmitted, busy = false, service = defaultService }: Props) {
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [ref, setRef] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const urlId = useId();
  const refId = useId();
  const errorId = useId();

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitError(null);
    const invalid = validateScanInput(repositoryUrl, ref);
    if (invalid) {
      setSubmitError(invalid);
      return;
    }
    setSubmitting(true);
    try {
      const created = await service.createScan(buildScanRequest(repositoryUrl, ref));
      onSubmitted(created);
    } catch (error) {
      setSubmitError(getFriendlyError(error));
    } finally {
      setSubmitting(false);
    }
  }

  const disabled = submitting || busy;

  return (
    <form onSubmit={onSubmit} noValidate className="grid gap-3 md:grid-cols-[minmax(0,1fr)_220px_auto] md:items-end">
      <div className="grid gap-1.5">
        <label htmlFor={urlId} className="text-sm font-medium">GitHub repository URL</label>
        <Input
          id={urlId}
          name="repository_url"
          type="url"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="https://github.com/owner/repo"
          value={repositoryUrl}
          onChange={(e) => setRepositoryUrl(e.target.value)}
          aria-invalid={submitError ? true : undefined}
          aria-describedby={submitError ? errorId : undefined}
          className="h-10"
        />
      </div>
      <div className="grid gap-1.5">
        <label htmlFor={refId} className="text-sm font-medium">
          Branch/tag <span className="font-normal text-muted-foreground">(optional)</span>
        </label>
        <div className="relative">
          <GitBranch className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            id={refId}
            name="ref"
            autoComplete="off"
            spellCheck={false}
            placeholder="default branch"
            value={ref}
            onChange={(e) => setRef(e.target.value)}
            className="h-10 pl-8"
          />
        </div>
      </div>
      <Button type="submit" size="lg" className="h-10 px-4" disabled={disabled}>
        {submitting ? <Loader2 className="animate-spin" aria-hidden /> : <Search aria-hidden />}
        {submitting ? "Submitting…" : "Scan repository"}
      </Button>
      {submitError && (
        <p id={errorId} role="alert" className="text-sm text-destructive md:col-span-3">
          {submitError}
        </p>
      )}
    </form>
  );
}
