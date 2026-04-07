import { describe, it, expect } from "vitest";
import { allowIPSchema } from "../tools/allow-ip.js";
import { denyIPSchema } from "../tools/deny-ip.js";
import { disableRuleSchema } from "../tools/disable-rule.js";
import { enableRuleSchema } from "../tools/enable-rule.js";

describe("allowIPSchema", () => {
  it("accepts valid IPv4", () => {
    expect(allowIPSchema.parse({ ip: "192.168.1.1" })).toEqual({ ip: "192.168.1.1" });
  });

  it("accepts valid CIDR", () => {
    expect(allowIPSchema.parse({ ip: "10.0.0.0/24" })).toEqual({ ip: "10.0.0.0/24" });
  });

  it("rejects ModSec directive injection", () => {
    expect(() =>
      allowIPSchema.parse({ ip: '127.0.0.1" "id:99999,phase:1,pass,exec:/bin/sh' }),
    ).toThrow();
  });

  it("rejects shell metacharacters", () => {
    expect(() => allowIPSchema.parse({ ip: "127.0.0.1; rm -rf /" })).toThrow();
  });

  it("rejects empty string", () => {
    expect(() => allowIPSchema.parse({ ip: "" })).toThrow();
  });

  it("rejects random text", () => {
    expect(() => allowIPSchema.parse({ ip: "not-an-ip" })).toThrow();
  });

  it("rejects IPv6 (current schema is IPv4-only)", () => {
    expect(() => allowIPSchema.parse({ ip: "::1" })).toThrow();
  });
});

describe("denyIPSchema", () => {
  it("accepts valid IPv4", () => {
    expect(denyIPSchema.parse({ ip: "10.20.30.40" })).toEqual({ ip: "10.20.30.40" });
  });

  it("rejects injection via ipMatch filter", () => {
    expect(() =>
      denyIPSchema.parse({ ip: '10.0.0.1") || true || ("' }),
    ).toThrow();
  });
});

describe("disableRuleSchema", () => {
  it("accepts numeric rule ID", () => {
    expect(disableRuleSchema.parse({ ruleId: "942140" })).toEqual({ ruleId: "942140" });
  });

  it("rejects newline injection", () => {
    expect(() =>
      disableRuleSchema.parse({ ruleId: "942140\nSecRuleEngine Off" }),
    ).toThrow();
  });

  it("rejects non-numeric", () => {
    expect(() => disableRuleSchema.parse({ ruleId: "abc" })).toThrow();
  });

  it("rejects empty string", () => {
    expect(() => disableRuleSchema.parse({ ruleId: "" })).toThrow();
  });

  it("rejects rule ID with spaces", () => {
    expect(() => disableRuleSchema.parse({ ruleId: "942 140" })).toThrow();
  });
});

describe("enableRuleSchema", () => {
  it("accepts numeric rule ID", () => {
    expect(enableRuleSchema.parse({ ruleId: "100000" })).toEqual({ ruleId: "100000" });
  });

  it("rejects directive injection", () => {
    expect(() =>
      enableRuleSchema.parse({ ruleId: "942140\nSecRuleRemoveById *" }),
    ).toThrow();
  });
});
