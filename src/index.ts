import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import WAFManager from "./waf-manager.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(__dirname, "..", "package.json"), "utf-8"));

// Analysis tools (drill-down pipeline)
import { overviewSchema, overviewHandler } from "./tools/overview.js";
import { topIPsSchema, topIPsHandler } from "./tools/top-ips.js";
import { topRulesSchema, topRulesHandler } from "./tools/top-rules.js";
import { fpCandidatesSchema, fpCandidatesHandler } from "./tools/fp-candidates.js";
import { eventsByIPSchema, eventsByIPHandler } from "./tools/events-by-ip.js";
import { eventsByRuleSchema, eventsByRuleHandler } from "./tools/events-by-rule.js";
import { eventDetailSchema, eventDetailHandler } from "./tools/event-detail.js";

// Action tools
import { statusSchema, statusHandler } from "./tools/status.js";
import { setEngineSchema, setEngineHandler } from "./tools/set-engine.js";
import { setParanoiaSchema, setParanoiaHandler } from "./tools/set-paranoia.js";
import { disableRuleSchema, disableRuleHandler } from "./tools/disable-rule.js";
import { enableRuleSchema, enableRuleHandler } from "./tools/enable-rule.js";
import { allowIPSchema, allowIPHandler } from "./tools/allow-ip.js";
import { denyIPSchema, denyIPHandler } from "./tools/deny-ip.js";
import { testSchema, testHandler } from "./tools/test.js";

const server = new McpServer({ name: "waf", version: pkg.version });
const waf = new WAFManager();

// ---------------------------------------------------------------------------
// Analysis tools — drill-down pipeline
// ---------------------------------------------------------------------------

server.tool(
  "waf_overview",
  "High-level WAF dashboard: total events, unique IPs, unique rules, events in last hour. Start here to assess if anything needs attention.",
  overviewSchema.shape,
  overviewHandler(waf),
);

server.tool(
  "waf_top_ips",
  "Top attacking IPs with hit counts, geo info, and last seen timestamp. Use to identify most active sources.",
  topIPsSchema.shape,
  topIPsHandler(waf),
);

server.tool(
  "waf_top_rules",
  "Most frequently triggered WAF rules with severity and description. Use to identify dominant attack patterns.",
  topRulesSchema.shape,
  topRulesHandler(waf),
);

server.tool(
  "waf_fp_candidates",
  "Rules that triggered on HTTP 2xx responses — likely false positives. Critical for WAF tuning.",
  fpCandidatesSchema.shape,
  fpCandidatesHandler(waf),
);

server.tool(
  "waf_events_by_ip",
  "Drill into events from a specific IP address. Shows timestamps, methods, URIs, HTTP codes, and triggered rules.",
  eventsByIPSchema.shape,
  eventsByIPHandler(waf),
);

server.tool(
  "waf_events_by_rule",
  "Drill into events that triggered a specific rule. Shows timestamps, IPs, methods, URIs, HTTP codes, and matched data.",
  eventsByRuleSchema.shape,
  eventsByRuleHandler(waf),
);

server.tool(
  "waf_event_detail",
  "Full deep-dive into a single event by index. Shows all request headers, body snippet, all rule matches with matched data, and response code.",
  eventDetailSchema.shape,
  eventDetailHandler(waf),
);

// ---------------------------------------------------------------------------
// Action tools
// ---------------------------------------------------------------------------

server.tool(
  "waf_status",
  "Get WAF container health, engine mode, rules loaded, and paranoia level.",
  statusSchema.shape,
  statusHandler(waf),
);

server.tool(
  "waf_set_engine",
  "Change WAF engine mode: On (actively blocking), Off (disabled), or DetectionOnly (log without blocking).",
  setEngineSchema.shape,
  setEngineHandler(waf),
);

server.tool(
  "waf_set_paranoia",
  "Set CRS paranoia level (1-4). Level 1 is minimal rules, level 4 is maximum security with more false positives.",
  setParanoiaSchema.shape,
  setParanoiaHandler(waf),
);

server.tool(
  "waf_disable_rule",
  "Disable a specific ModSecurity rule by ID to suppress false positives.",
  disableRuleSchema.shape,
  disableRuleHandler(waf),
);

server.tool(
  "waf_enable_rule",
  "Re-enable a previously disabled ModSecurity rule by ID.",
  enableRuleSchema.shape,
  enableRuleHandler(waf),
);

server.tool(
  "waf_allow_ip",
  "Whitelist an IP address to bypass WAF inspection entirely.",
  allowIPSchema.shape,
  allowIPHandler(waf),
);

server.tool(
  "waf_deny_ip",
  "Remove an IP address from the WAF whitelist.",
  denyIPSchema.shape,
  denyIPHandler(waf),
);

server.tool(
  "waf_test",
  "Run the WAF test suite to verify blocking and pass-through rules are working correctly.",
  testSchema.shape,
  testHandler(waf),
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
