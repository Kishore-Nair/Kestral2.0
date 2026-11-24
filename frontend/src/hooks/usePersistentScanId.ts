"use client";

import { useCallback, useEffect, useState } from "react";

const PARAM = "scan";
const SAFE_ID = /^[A-Za-z0-9_-]{1,80}$/;

function writeUrl(id: string | null) {
  const url = new URL(window.location.href);
  if (id) url.searchParams.set(PARAM, id);
  else url.searchParams.delete(PARAM);
  // replaceState keeps Next.js from re-rendering the route and avoids history spam.
  window.history.replaceState(window.history.state, "", url);
}

/**
 * Keeps the active scan ID in the `?scan=` query parameter so a refresh, a bookmark or a shared
 * link reopens the same scan instead of an empty form.
 */
export function usePersistentScanId(): [string | null, (id: string | null) => void] {
  const [scanId, setScanIdState] = useState<string | null>(null);

  useEffect(() => {
    const fromUrl = new URL(window.location.href).searchParams.get(PARAM);
    if (fromUrl && SAFE_ID.test(fromUrl)) setScanIdState(fromUrl);
    else if (fromUrl) writeUrl(null);
  }, []);

  const setScanId = useCallback((id: string | null) => {
    const safe = id && SAFE_ID.test(id) ? id : null;
    setScanIdState(safe);
    writeUrl(safe);
  }, []);

  return [scanId, setScanId];
}

/** Ask the browser to confirm before a refresh or tab close while `active` is true. */
export function useConfirmBeforeUnload(active: boolean) {
  useEffect(() => {
    if (!active) return;
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      // Required by some browsers to show the native "Leave site?" prompt.
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [active]);
}
