import { describe, it, expect } from "vitest";
import {
  tagResourceProvenance,
  registerContextEvictionHook,
  evictContext,
} from "./provenance.js";

describe("provenance", () => {
  it("tags resource text", () => {
    const r = tagResourceProvenance({
      contents: [{ uri: "file://x", text: "hello", mimeType: "text/plain" }],
    } as any);
    const text = (r.contents[0] as { text: string }).text;
    expect(text).toContain("<untrusted_resource>");
    expect(text).toContain("hello");
  });

  it("evicts via registered hook", () => {
    const seen: string[] = [];
    const unreg = registerContextEvictionHook((id) => seen.push(id));
    evictContext("sess-1");
    expect(seen).toEqual(["sess-1"]);
    unreg();
  });
});
