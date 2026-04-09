/**
 * Integration test: compares WAFManager output against raw docker logs.
 *
 * Skipped by default — only runs when WAF_INTEGRATION_TEST=1 is set
 * and a real ModSecurity container is running.
 *
 * Run: WAF_INTEGRATION_TEST=1 WAF_COMPOSE_DIR=/home/xpanceo/LiteLLM npm test
 */
import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";

const SKIP = !process.env.WAF_INTEGRATION_TEST;
const SINCE = process.env.WAF_TEST_SINCE ?? "48h";

// Find container name the same way WAFManager does
function findContainer(): string {
  const pattern = process.env.WAF_CONTAINER_PATTERN ?? "modsecurity";
  return execSync(
    `docker ps --format '{{.Names}}' | grep -i ${pattern} | head -1`,
    { encoding: "utf-8" },
  ).trim();
}

// Get raw events via grep (ground truth)
function getRawEvents(container: string): Array<Record<string, unknown>> {
  const output = execSync(
    `docker logs --since ${SINCE} ${container} 2>&1 | grep '^{"transaction"'`,
    { encoding: "utf-8", maxBuffer: 50 * 1024 * 1024 },
  ).trim();
  if (!output) return [];
  return output
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean) as Array<Record<string, unknown>>;
}

// Extract IP from raw event (same logic as WAFManager)
function extractIP(raw: Record<string, unknown>): string {
  const t = raw.transaction as Record<string, unknown>;
  const req = t?.request as Record<string, unknown>;
  const headers = req?.headers as Record<string, string>;
  return headers?.["X-Real-Ip"] ?? headers?.["x-real-ip"] ?? (t?.client_ip as string) ?? "unknown";
}

// Extract rules from raw event
function extractRules(raw: Record<string, unknown>): string[] {
  const t = raw.transaction as Record<string, unknown>;
  const messages = t?.messages as Array<Record<string, unknown>>;
  if (!Array.isArray(messages)) return [];
  return messages
    .map((m) => {
      const details = m.details as Record<string, unknown>;
      return details?.ruleId as string;
    })
    .filter(Boolean);
}

describe.skipIf(SKIP)("Integration: WAFManager vs raw docker logs", () => {
  let container: string;
  let rawEvents: Array<Record<string, unknown>>;
  let waf: InstanceType<typeof import("../waf-manager.js").default>;

  it("setup: find container and load WAFManager", async () => {
    container = findContainer();
    expect(container).toBeTruthy();

    rawEvents = getRawEvents(container);

    // Dynamic import to use real config (not mocked)
    const mod = await import("../waf-manager.js");
    waf = new mod.default();
  });

  it("event count matches", async () => {
    const overview = await waf.getOverview(SINCE);
    expect(overview.totalEvents).toBe(rawEvents.length);
  });

  it("unique IPs match", async () => {
    const overview = await waf.getOverview(SINCE);
    const rawIPs = new Set(rawEvents.map(extractIP));
    expect(overview.uniqueIPs).toBe(rawIPs.size);
  });

  it("unique rules match", async () => {
    const overview = await waf.getOverview(SINCE);
    const rawRuleIDs = new Set<string>();
    for (const e of rawEvents) {
      for (const r of extractRules(e)) {
        rawRuleIDs.add(r);
      }
    }
    expect(overview.uniqueRules).toBe(rawRuleIDs.size);
  });

  it("top IPs are consistent with raw data", async () => {
    const topIPs = await waf.getTopIPs(5, SINCE);
    const rawIPCounts = new Map<string, number>();
    for (const e of rawEvents) {
      const ip = extractIP(e);
      rawIPCounts.set(ip, (rawIPCounts.get(ip) ?? 0) + 1);
    }

    for (const entry of topIPs) {
      const rawCount = rawIPCounts.get(entry.ip) ?? 0;
      expect(entry.count).toBe(rawCount);
    }
  });

  it("top rules are consistent with raw data", async () => {
    const topRules = await waf.getTopRules(5, SINCE);
    const rawRuleCounts = new Map<string, number>();
    for (const e of rawEvents) {
      for (const r of extractRules(e)) {
        rawRuleCounts.set(r, (rawRuleCounts.get(r) ?? 0) + 1);
      }
    }

    for (const entry of topRules) {
      const rawCount = rawRuleCounts.get(entry.ruleId) ?? 0;
      expect(entry.count).toBe(rawCount);
    }
  });

  it("events_by_ip returns correct count for top IP", async () => {
    const topIPs = await waf.getTopIPs(1, SINCE);
    if (topIPs.length === 0) return; // no events

    const ip = topIPs[0].ip;
    const events = await waf.getEventsByIP(ip, 1000, SINCE);
    expect(events.length).toBe(topIPs[0].count);
  });

  it("every event has valid fields", async () => {
    const overview = await waf.getOverview(SINCE);
    if (overview.totalEvents === 0) return;

    // Spot-check first 10 events via events_by_ip on the top IP
    const topIPs = await waf.getTopIPs(1, SINCE);
    if (topIPs.length === 0) return;

    const events = await waf.getEventsByIP(topIPs[0].ip, 10, SINCE);
    for (const e of events) {
      expect(e.index).toBeTypeOf("number");
      expect(e.timestamp).toBeTruthy();
      expect(e.method).toBeTruthy();
      expect(e.uri).toBeTruthy();
      expect(e.httpCode).toBeTypeOf("number");
      expect(Array.isArray(e.rules)).toBe(true);
    }
  });

  it("event_detail returns valid detail for first event", async () => {
    const overview = await waf.getOverview(SINCE);
    if (overview.totalEvents === 0) return;

    const detail = await waf.getEventDetail(0, false, SINCE);
    expect(detail.index).toBe(0);
    expect(detail.sourceIp).toBeTruthy();
    expect(detail.method).toBeTruthy();
    expect(typeof detail.requestHeaders).toBe("object");
    expect(Array.isArray(detail.rules)).toBe(true);
  });

  it("FP candidates only contain rules from 2xx events", async () => {
    const candidates = await waf.getFPCandidates(SINCE);
    const rawFPRules = new Set<string>();
    for (const e of rawEvents) {
      const t = e.transaction as Record<string, unknown>;
      const resp = t?.response as Record<string, unknown>;
      const code = resp?.http_code as number;
      if (code >= 200 && code < 300) {
        for (const r of extractRules(e)) {
          rawFPRules.add(r);
        }
      }
    }

    for (const c of candidates) {
      expect(rawFPRules.has(c.ruleId)).toBe(true);
    }
  });
});
