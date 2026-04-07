# WAF MCP Server

An MCP (Model Context Protocol) server for managing [OWASP ModSecurity CRS](https://coreruleset.org/) via Docker. Gives AI assistants like Claude direct access to WAF monitoring, analysis, and configuration through a structured drill-down pipeline.

Built for [Claude Code](https://claude.com/claude-code) but works with any MCP-compatible client.

## Why

LLM proxy services (LiteLLM, OpenRouter, etc.) sit behind WAFs that generate massive amounts of false positives — prompts contain code, SQL, HTML, shell commands that trigger every content-inspection rule in the book. Managing these WAFs requires constant monitoring, tuning exclusions, and investigating events.

This MCP server lets an AI assistant do that work directly:

1. **Overview** — see total events, unique IPs, active rules at a glance
2. **Drill down** — filter events by IP or rule, inspect matched data
3. **Act** — disable rules, whitelist IPs, change engine mode — all without leaving the conversation

## Tools

### Analysis (drill-down pipeline)

| Tool | Description |
|------|-------------|
| `waf_overview` | Dashboard: total events, unique IPs/rules, events last hour |
| `waf_top_ips` | Top IPs by event count with geo enrichment (ipinfo.io) |
| `waf_top_rules` | Most triggered rules with severity and description |
| `waf_fp_candidates` | Rules that fired on HTTP 2xx responses (false positive candidates) |
| `waf_events_by_ip` | Events filtered by source IP |
| `waf_events_by_rule` | Events filtered by rule ID |
| `waf_event_detail` | Full event: headers, request body, all rule matches with matched data |

### Actions

| Tool | Description |
|------|-------------|
| `waf_status` | Container health, engine mode, rules loaded, paranoia level |
| `waf_set_engine` | Switch between `On`, `Off`, `DetectionOnly` |
| `waf_set_paranoia` | Set CRS paranoia level (1–4) |
| `waf_disable_rule` | Disable a rule by ID (adds `SecRuleRemoveById` to exclusions) |
| `waf_enable_rule` | Re-enable a previously disabled rule |
| `waf_allow_ip` | Whitelist an IP (bypass WAF entirely) |
| `waf_deny_ip` | Remove an IP from whitelist |
| `waf_test` | Run test suite: scanner detection, SQLi, XSS, path traversal |

### Verbose mode

`waf_events_by_ip`, `waf_events_by_rule`, and `waf_event_detail` accept a `verbose: true` parameter. By default, `matchedData` and `requestBody` are truncated to keep responses within context limits. With `verbose: true`, matched data expands to 4000 chars per rule and request body to 8KB.

## Prerequisites

- **Docker** with a running [owasp/modsecurity-crs](https://hub.docker.com/r/owasp/modsecurity-crs) container
- **Docker Compose** managing the ModSecurity container
- **Node.js** 18+
- ModSecurity configured with **JSON Serial audit log** (`SecAuditLogFormat JSON`)

## Installation

```bash
git clone https://github.com/KratosUAE/waf_mcp.git
cd waf_mcp
npm install
npm run build
```

## Configuration

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WAF_COMPOSE_DIR` | **Yes** | — | Path to directory containing `docker-compose.yml` |
| `WAF_DOMAIN` | No | `https://localhost` | Domain for WAF test requests |
| `WAF_CONTAINER_PATTERN` | No | `modsecurity` | Grep pattern to find the ModSecurity container |
| `WAF_EXCLUSIONS_FILE` | No | `modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | Path to CRS exclusions file (relative to compose dir) |
| `WAF_COMPOSE_FILE` | No | `docker-compose.yml` | Docker Compose filename |
| `IPINFO_TOKEN` | No | — | [ipinfo.io](https://ipinfo.io) token for IP geolocation |
| `WAF_DEBUG` | No | — | Set to any value to enable debug logging |

### Connect to Claude Code

```bash
claude mcp add --transport stdio --scope user \
  -e WAF_COMPOSE_DIR=/path/to/your/compose/dir \
  -e WAF_DOMAIN=https://your-domain.com \
  waf -- node /path/to/waf_mcp/dist/index.js
```

Or manually add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "waf": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/waf_mcp/dist/index.js"],
      "env": {
        "WAF_COMPOSE_DIR": "/path/to/your/compose/dir",
        "WAF_DOMAIN": "https://your-domain.com"
      }
    }
  }
}
```

### Docker Compose setup

The server expects a ModSecurity container managed by Docker Compose. Example service definition:

```yaml
modsecurity:
  image: owasp/modsecurity-crs:nginx-alpine
  environment:
    - BACKEND=http://your-app:8080
    - MODSEC_RULE_ENGINE=DetectionOnly
    - MODSEC_AUDIT_LOG=/dev/stderr
    - MODSEC_AUDIT_LOG_FORMAT=JSON
    - MODSEC_AUDIT_LOG_TYPE=Serial
    - MODSEC_AUDIT_ENGINE=RelevantOnly
    - MODSEC_REQ_BODY_ACCESS=On
    - MODSEC_REQ_BODY_LIMIT=52428800
    - MODSEC_RESP_BODY_ACCESS=Off
    - PARANOIA=1
    - ANOMALY_INBOUND=5
  volumes:
    - ./modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:ro
```

Key settings:
- **`MODSEC_AUDIT_LOG=/dev/stderr`** — sends audit log to Docker logs (required for the MCP server to read events)
- **`MODSEC_AUDIT_LOG_FORMAT=JSON`** — JSON format for structured parsing
- **Exclusions file mount** — allows hot-reload of rule exclusions via `nginx -s reload`

### CRS exclusions for LLM traffic

LLM API endpoints receive prompts containing code, SQL, HTML, and shell commands — all legitimate content that triggers WAF rules. Create an exclusions file to disable content-inspection rules on API paths:

```apache
# modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
SecRule REQUEST_URI "@rx ^(/v1/)?(chat/completions|completions|embeddings|responses|messages)|^/anthropic/" \
    "id:1000,phase:1,nolog,pass,\
    ctl:ruleRemoveById=921000-944999"
```

This disables rules 921000–944999 (all content-inspection categories: SQLi, XSS, RCE, LFI, RFI, etc.) on LLM API endpoints while keeping protocol enforcement, scanner detection, DoS protection, and IP reputation checks active.

## Usage example

Typical workflow in Claude Code:

```
You: "Check the WAF — anything suspicious?"

Claude: [calls waf_overview]
  → 332 events, 4 unique IPs, 12 rules triggered

Claude: [calls waf_top_ips]
  → 135.237.83.23 (Washington, US, Microsoft) — 320 events

Claude: [calls waf_events_by_ip, ip: "135.237.83.23", count: 5]
  → All POST /chat/completions, HTTP 200, rules: 942360, 932100...

Claude: [calls waf_event_detail, index: 42]
  → User-Agent: OpenAI/JS 6.26.0, body contains tool descriptions
  → Rule 942360 matched "update" in cron action descriptions

Claude: "This is your OpenClaw bot — all false positives. 
         Want me to whitelist this IP?"

You: "Yes"

Claude: [calls waf_allow_ip, ip: "135.237.83.23"]
  → Done. IP whitelisted.
```

## Development

```bash
npm run build        # Compile TypeScript
npm test             # Run tests (43 tests)
npm run test:watch   # Watch mode
WAF_DEBUG=1 npm start  # Run with debug logging
```

## Architecture

```
src/
├── index.ts           # MCP server setup, tool registration
├── waf-manager.ts     # Core service: Docker exec, log parsing, config management
├── types.ts           # TypeScript interfaces
├── config.ts          # Environment-based configuration
├── logger.ts          # stderr-only logger (stdout reserved for MCP protocol)
└── tools/
    ├── overview.ts        # L0: dashboard
    ├── top-ips.ts         # L1: IP aggregation
    ├── top-rules.ts       # L1: rule aggregation
    ├── fp-candidates.ts   # L1: false positive detection
    ├── events-by-ip.ts    # L2: drill-down by IP
    ├── events-by-rule.ts  # L2: drill-down by rule
    ├── event-detail.ts    # L3: full event inspection
    ├── status.ts          # Container status
    ├── set-engine.ts      # Engine mode control
    ├── set-paranoia.ts    # Paranoia level control
    ├── disable-rule.ts    # Rule management
    ├── enable-rule.ts     # Rule management
    ├── allow-ip.ts        # IP whitelist
    ├── deny-ip.ts         # IP whitelist
    ├── test.ts            # WAF test suite
    └── utils.ts           # Shared utilities
```

Events are parsed from Docker logs and cached for 30 seconds. Rapid drill-down calls (overview → top IPs → events by IP → event detail) hit the cache instead of re-parsing.

## License

MIT
