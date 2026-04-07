import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock logger and fs before importing config
vi.mock("../logger.js", () => ({
  logger: { info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

describe("getConfig — containerPattern validation", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("accepts alphanumeric pattern", async () => {
    vi.stubEnv("WAF_COMPOSE_DIR", "/tmp");
    vi.stubEnv("WAF_CONTAINER_PATTERN", "modsec-waf_v2.1");

    // Mock existsSync to return true for /tmp
    vi.doMock("node:fs", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      return { ...actual, existsSync: () => true };
    });

    const { getConfig } = await import("../config.js");
    const config = getConfig();
    expect(config.containerPattern).toBe("modsec-waf_v2.1");

    vi.unstubAllEnvs();
  });

  it("rejects pattern with shell metacharacters", async () => {
    vi.stubEnv("WAF_COMPOSE_DIR", "/tmp");
    vi.stubEnv("WAF_CONTAINER_PATTERN", "modsec; rm -rf /");

    vi.doMock("node:fs", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      return { ...actual, existsSync: () => true };
    });

    const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });

    const { getConfig } = await import("../config.js");
    expect(() => getConfig()).toThrow("process.exit called");
    expect(mockExit).toHaveBeenCalledWith(1);

    mockExit.mockRestore();
    vi.unstubAllEnvs();
  });

  it("exits when WAF_COMPOSE_DIR is not set", async () => {
    vi.stubEnv("WAF_COMPOSE_DIR", "");

    const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });

    const { getConfig } = await import("../config.js");
    expect(() => getConfig()).toThrow("process.exit called");
    expect(mockExit).toHaveBeenCalledWith(1);

    mockExit.mockRestore();
    vi.unstubAllEnvs();
  });
});
