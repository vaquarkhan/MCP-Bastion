import { describe, it, expect } from "vitest";
import {
  checkEgressAllowlist,
  extractHostname,
  hostAllowed,
} from "./egress-allowlist.js";

describe("egress-allowlist", () => {
  it("extracts host from URL", () => {
    expect(extractHostname("https://api.example.com/v1")).toBe("api.example.com");
  });

  it("allows wildcard suffix", () => {
    expect(hostAllowed("a.b.example.com", ["*.example.com"])).toBe(true);
    expect(hostAllowed("evil.com", ["*.example.com"])).toBe(false);
  });

  it("denies non-allowlisted host on egress tool", () => {
    const r = checkEgressAllowlist(
      "http_fetch",
      { url: "https://evil.example/x" },
      { allowedHosts: ["api.good.com"] }
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.deniedHost).toBe("evil.example");
  });

  it("allows allowlisted host", () => {
    const r = checkEgressAllowlist(
      "send_email",
      { to: "https://mail.company.com/send" },
      { allowedHosts: ["mail.company.com"] }
    );
    expect(r.ok).toBe(true);
  });

  it("skips non-egress tools", () => {
    const r = checkEgressAllowlist(
      "read_file",
      { path: "https://evil.com" },
      { allowedHosts: [] }
    );
    expect(r.ok).toBe(true);
  });
});
