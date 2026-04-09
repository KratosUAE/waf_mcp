import { z } from "zod";
import type WAFManager from "../waf-manager.js";
import { truncate, ipPattern } from "./utils.js";

export const eventsByIPSchema = z.object({
  ip: z.string().regex(ipPattern, "Must be a valid IPv4 address (e.g. 192.168.1.1)").describe("IP address to filter events by"),
  count: z.number().optional().default(20).describe("Number of events to return (default 20)"),
  verbose: z.boolean().optional().default(false).describe("Include full matched data in rules (default: truncated)"),
  since: z.string().optional().default("24h").describe("Time window for log search (e.g. '1h', '24h', '7d'). Default: 24h"),
});

export function eventsByIPHandler(waf: WAFManager) {
  return async (args: z.infer<typeof eventsByIPSchema>) => {
    try {
      const data = await waf.getEventsByIP(args.ip, args.count, args.since);

      const result = args.verbose
        ? data
        : data.map((e) => ({
            ...e,
            rules: e.rules.map((r) => ({
              id: r.id,
              message: r.message,
              severity: r.severity,
              ...(r.matchedData ? { matchedData: truncate(r.matchedData, 150) } : {}),
            })),
          }));

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
