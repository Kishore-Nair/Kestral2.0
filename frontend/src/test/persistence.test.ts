import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useConfirmBeforeUnload, usePersistentScanId } from "@/hooks/usePersistentScanId";

afterEach(() => window.history.replaceState(null, "", "/"));

describe("usePersistentScanId", () => {
  it("restores the scan from the URL after a refresh", () => {
    window.history.replaceState(null, "", "/?scan=scan_abc123");
    const { result } = renderHook(() => usePersistentScanId());
    expect(result.current[0]).toBe("scan_abc123");
  });

  it("writes and clears the scan in the URL", () => {
    const { result } = renderHook(() => usePersistentScanId());
    act(() => result.current[1]("scan_new"));
    expect(window.location.search).toBe("?scan=scan_new");
    act(() => result.current[1](null));
    expect(window.location.search).toBe("");
  });

  it("ignores unsafe values", () => {
    window.history.replaceState(null, "", "/?scan=%3Cscript%3E");
    const { result } = renderHook(() => usePersistentScanId());
    expect(result.current[0]).toBeNull();
    expect(window.location.search).toBe("");
  });
});

describe("useConfirmBeforeUnload", () => {
  it("only blocks unload while active", () => {
    const { rerender } = renderHook(({ active }) => useConfirmBeforeUnload(active), { initialProps: { active: true } });
    const blocked = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(blocked);
    expect(blocked.defaultPrevented).toBe(true);

    rerender({ active: false });
    const allowed = new Event("beforeunload", { cancelable: true });
    const spy = vi.spyOn(allowed, "preventDefault");
    window.dispatchEvent(allowed);
    expect(spy).not.toHaveBeenCalled();
  });
});
