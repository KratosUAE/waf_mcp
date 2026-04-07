import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Mock child_process before importing WAFManager
const execMock = vi.fn();
vi.mock("node:child_process", () => ({
  exec: execMock,
}));

// Mock config
let testDir: string;
vi.mock("../config.js", () => ({
  getConfig: () => ({
    composeDir: testDir,
    containerPattern: "modsecurity",
    domain: "https://localhost",
    exclusionsFile: "exclusions.conf",
    composeFile: "docker-compose.yml",
    ipinfoToken: undefined,
  }),
}));

// Mock logger
vi.mock("../logger.js", () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Helper: make execMock call the callback with given stdout
function mockExecSuccess(stdout: string) {
  execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => {
    cb(null, { stdout, stderr: "" });
  });
}

function mockExecSuccessSequence(responses: string[]) {
  let callIndex = 0;
  execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => {
    const stdout = responses[callIndex] ?? "";
    callIndex++;
    cb(null, { stdout, stderr: "" });
  });
}

function mockExecFailure(message: string) {
  execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => {
    cb(new Error(message));
  });
}

describe("WAFManager", () => {
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), "waf-test-"));
    // Create compose file
    writeFileSync(
      join(testDir, "docker-compose.yml"),
      "services:\n  modsecurity:\n    environment:\n      - MODSEC_RULE_ENGINE=On\n      - PARANOIA=2\n",
    );
    execMock.mockReset();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  async function loadWAFManager() {
    // Dynamic import to pick up fresh mocks
    const mod = await import("../waf-manager.js");
    return new mod.default();
  }

  // ---------------------------------------------------------------------------
  // disableRule
  // ---------------------------------------------------------------------------

  describe("disableRule", () => {
    it("writes SecRuleRemoveById to exclusions file", async () => {
      const waf = await loadWAFManager();
      // findContainer + reloadRules
      mockExecSuccessSequence(["modsec-container", "ok"]);

      const result = await waf.disableRule("942140");
      expect(result.success).toBe(true);

      const content = readFileSync(join(testDir, "exclusions.conf"), "utf-8");
      expect(content).toContain("SecRuleRemoveById 942140");
      expect(content).toContain("# Disabled rule 942140");
    });

    it("does not duplicate if rule already disabled", async () => {
      const waf = await loadWAFManager();
      writeFileSync(
        join(testDir, "exclusions.conf"),
        "\n# Disabled rule 942140\nSecRuleRemoveById 942140\n",
      );

      const result = await waf.disableRule("942140");
      expect(result.success).toBe(true);
      expect(result.output).toContain("already disabled");
      // exec should NOT have been called (no reload needed)
      expect(execMock).not.toHaveBeenCalled();
    });
  });

  // ---------------------------------------------------------------------------
  // enableRule
  // ---------------------------------------------------------------------------

  describe("enableRule", () => {
    it("removes SecRuleRemoveById from exclusions file", async () => {
      const waf = await loadWAFManager();
      writeFileSync(
        join(testDir, "exclusions.conf"),
        "# some header\n# Disabled rule 942140\nSecRuleRemoveById 942140\n# Disabled rule 920350\nSecRuleRemoveById 920350\n",
      );
      mockExecSuccessSequence(["modsec-container", "ok"]);

      const result = await waf.enableRule("942140");
      expect(result.success).toBe(true);

      const content = readFileSync(join(testDir, "exclusions.conf"), "utf-8");
      expect(content).not.toContain("942140");
      expect(content).toContain("SecRuleRemoveById 920350");
    });

    it("returns error if exclusions file does not exist", async () => {
      const waf = await loadWAFManager();
      const result = await waf.enableRule("942140");
      expect(result.success).toBe(false);
      expect(result.output).toContain("not found");
    });
  });

  // ---------------------------------------------------------------------------
  // allowIP — ID generation
  // ---------------------------------------------------------------------------

  describe("allowIP", () => {
    it("starts IDs at 90000", async () => {
      const waf = await loadWAFManager();
      mockExecSuccessSequence(["modsec-container", "ok"]);

      await waf.allowIP("10.0.0.1");
      const content = readFileSync(join(testDir, "exclusions.conf"), "utf-8");
      expect(content).toContain("id:90000");
      expect(content).toContain('@ipMatch 10.0.0.1');
    });

    it("increments IDs for subsequent IPs", async () => {
      const waf = await loadWAFManager();
      writeFileSync(
        join(testDir, "exclusions.conf"),
        '# Whitelist IP 10.0.0.1\nSecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:90000,phase:1,allow,nolog,ctl:ruleEngine=Off"\n',
      );
      mockExecSuccessSequence(["modsec-container", "ok"]);

      await waf.allowIP("10.0.0.2");
      const content = readFileSync(join(testDir, "exclusions.conf"), "utf-8");
      expect(content).toContain("id:90001");
    });

    it("does not collide with CRS rule IDs", async () => {
      const waf = await loadWAFManager();
      // File has CRS rules with id:100000+, but no whitelist rules
      writeFileSync(
        join(testDir, "exclusions.conf"),
        'SecRuleRemoveById 100000\nSecRule TX "id:100001,phase:2"\n',
      );
      mockExecSuccessSequence(["modsec-container", "ok"]);

      await waf.allowIP("10.0.0.1");
      const content = readFileSync(join(testDir, "exclusions.conf"), "utf-8");
      // Should still start at 90000, not jump to 100002
      expect(content).toContain("id:90000");
    });
  });

  // ---------------------------------------------------------------------------
  // denyIP
  // ---------------------------------------------------------------------------

  describe("denyIP", () => {
    it("removes IP whitelist entry from exclusions file", async () => {
      const waf = await loadWAFManager();
      writeFileSync(
        join(testDir, "exclusions.conf"),
        '# Whitelist IP 10.0.0.1\nSecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:90000,phase:1,allow"\n# Whitelist IP 10.0.0.2\nSecRule REMOTE_ADDR "@ipMatch 10.0.0.2" "id:90001,phase:1,allow"\n',
      );
      mockExecSuccessSequence(["modsec-container", "ok"]);

      const result = await waf.denyIP("10.0.0.1");
      expect(result.success).toBe(true);

      const content = readFileSync(join(testDir, "exclusions.conf"), "utf-8");
      expect(content).not.toContain("10.0.0.1");
      expect(content).toContain("10.0.0.2");
    });

    it("returns success when exclusions file does not exist", async () => {
      const waf = await loadWAFManager();
      const result = await waf.denyIP("10.0.0.1");
      expect(result.success).toBe(true);
      expect(result.output).toContain("not whitelisted");
    });
  });

  // ---------------------------------------------------------------------------
  // setParanoia
  // ---------------------------------------------------------------------------

  describe("setParanoia", () => {
    it("rejects level below 1", async () => {
      const waf = await loadWAFManager();
      const result = await waf.setParanoia(0);
      expect(result.success).toBe(false);
    });

    it("rejects level above 4", async () => {
      const waf = await loadWAFManager();
      const result = await waf.setParanoia(5);
      expect(result.success).toBe(false);
    });

    it("replaces multi-digit paranoia values correctly", async () => {
      const waf = await loadWAFManager();
      // Edge case: PARANOIA=10 (invalid but possible)
      writeFileSync(
        join(testDir, "docker-compose.yml"),
        "PARANOIA=10\n",
      );
      mockExecSuccessSequence(["modsec-container", "ok"]);

      const result = await waf.setParanoia(3);
      expect(result.success).toBe(true);

      const content = readFileSync(join(testDir, "docker-compose.yml"), "utf-8");
      expect(content).toBe("PARANOIA=3\n");
      expect(content).not.toContain("PARANOIA=10");
    });

    it("updates single-digit paranoia correctly", async () => {
      const waf = await loadWAFManager();
      mockExecSuccessSequence(["modsec-container", "ok"]);

      const result = await waf.setParanoia(4);
      expect(result.success).toBe(true);

      const content = readFileSync(join(testDir, "docker-compose.yml"), "utf-8");
      expect(content).toContain("PARANOIA=4");
      expect(content).not.toContain("PARANOIA=2");
    });
  });

  // ---------------------------------------------------------------------------
  // findContainer failure
  // ---------------------------------------------------------------------------

  describe("findContainer", () => {
    it("throws when no container found", async () => {
      const waf = await loadWAFManager();
      mockExecFailure("no container");
      await expect(waf.getStatus()).rejects.toThrow("No running ModSecurity container found");
    });
  });

  // ---------------------------------------------------------------------------
  // getOverview
  // ---------------------------------------------------------------------------

  describe("getOverview", () => {
    it("counts events, unique IPs and rules", async () => {
      const waf = await loadWAFManager();
      const now = new Date().toISOString();
      const logLines = [
        JSON.stringify({
          transaction: {
            time_stamp: now,
            client_ip: "1.2.3.4",
            request: { method: "GET", uri: "/test" },
            response: { http_code: 403 },
            messages: [{ details: { ruleId: "942140", severity: "CRITICAL", data: "" }, message: "SQL Injection" }],
          },
        }),
        JSON.stringify({
          transaction: {
            time_stamp: now,
            client_ip: "5.6.7.8",
            request: { method: "POST", uri: "/api" },
            response: { http_code: 403 },
            messages: [{ details: { ruleId: "941100", severity: "CRITICAL", data: "" }, message: "XSS" }],
          },
        }),
      ].join("\n");

      // findContainer, then docker logs for events
      mockExecSuccessSequence(["modsec-container", logLines]);

      const overview = await waf.getOverview();
      expect(overview.totalEvents).toBe(2);
      expect(overview.uniqueIPs).toBe(2);
      expect(overview.uniqueRules).toBe(2);
    });

    it("handles empty logs gracefully", async () => {
      const waf = await loadWAFManager();
      mockExecSuccessSequence(["modsec-container", ""]);

      const overview = await waf.getOverview();
      expect(overview.totalEvents).toBe(0);
      expect(overview.uniqueIPs).toBe(0);
    });

    it("handles malformed JSON lines gracefully", async () => {
      const waf = await loadWAFManager();
      const logLines = [
        "not-json",
        '{"transaction": null}',
        JSON.stringify({
          transaction: {
            time_stamp: new Date().toISOString(),
            client_ip: "1.2.3.4",
            request: { method: "GET", uri: "/" },
            response: { http_code: 200 },
            messages: [],
          },
        }),
      ].join("\n");
      mockExecSuccessSequence(["modsec-container", logLines]);

      const overview = await waf.getOverview();
      expect(overview.totalEvents).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  // getEventDetail
  // ---------------------------------------------------------------------------

  describe("getEventDetail", () => {
    it("throws for out-of-range index", async () => {
      const waf = await loadWAFManager();
      mockExecSuccessSequence(["modsec-container", ""]);

      await expect(waf.getEventDetail(0)).rejects.toThrow("out of range");
    });

    it("extracts headers and body from raw event", async () => {
      const waf = await loadWAFManager();
      const logLine = JSON.stringify({
        transaction: {
          time_stamp: "2024-01-01T00:00:00Z",
          client_ip: "1.2.3.4",
          request: {
            method: "POST",
            uri: "/api",
            headers: { "Content-Type": "application/json", "X-Real-Ip": "1.2.3.4" },
            body: '{"key":"value"}',
          },
          response: { http_code: 403 },
          messages: [{ details: { ruleId: "942140", severity: "CRITICAL", data: "matched" }, message: "SQLi" }],
        },
      });
      mockExecSuccessSequence(["modsec-container", logLine]);

      const detail = await waf.getEventDetail(0);
      expect(detail.sourceIp).toBe("1.2.3.4");
      expect(detail.requestHeaders["Content-Type"]).toBe("application/json");
      expect(detail.requestBody).toBe('{"key":"value"}');
      expect(detail.rules).toHaveLength(1);
      expect(detail.rules[0].id).toBe("942140");
    });
  });

  // ---------------------------------------------------------------------------
  // getFPCandidates
  // ---------------------------------------------------------------------------

  describe("getFPCandidates", () => {
    it("identifies rules triggered on 2xx responses as FP candidates", async () => {
      const waf = await loadWAFManager();
      const logLines = [
        // 200 + rule triggered = FP candidate
        JSON.stringify({
          transaction: {
            time_stamp: "2024-01-01T00:00:00Z",
            client_ip: "1.1.1.1",
            request: { method: "GET", uri: "/legit" },
            response: { http_code: 200 },
            messages: [{ details: { ruleId: "942140", severity: "CRITICAL", data: "" }, message: "SQLi" }],
          },
        }),
        // 403 + rule triggered = not FP
        JSON.stringify({
          transaction: {
            time_stamp: "2024-01-01T00:00:01Z",
            client_ip: "2.2.2.2",
            request: { method: "GET", uri: "/attack" },
            response: { http_code: 403 },
            messages: [{ details: { ruleId: "941100", severity: "CRITICAL", data: "" }, message: "XSS" }],
          },
        }),
      ].join("\n");
      mockExecSuccessSequence(["modsec-container", logLines]);

      const candidates = await waf.getFPCandidates();
      expect(candidates).toHaveLength(1);
      expect(candidates[0].ruleId).toBe("942140");
    });
  });
});
