import { z } from "zod";
import type WAFManager from "../waf-manager.js";
import { truncate } from "./utils.js";

export const eventsByRuleSchema = z.object({
  ruleId: z.string().describe("Rule ID to filter events by"),
  count: z.number().optional().default(20).describe("Number of events to return (default 20)"),
  verbose: z.boolean().optional().default(false).describe("Include full matched data (default: truncated)"),
  since: z.string().optional().default("24h").describe("Time window for log search (e.g. '1h', '24h', '7d'). Default: 24h"),
});

export function eventsByRuleHandler(waf: WAFManager) {
  return async (args: z.infer<typeof eventsByRuleSchema>) => {
    try {
      const data = await waf.getEventsByRule(args.ruleId, args.count, args.since);

      const result = args.verbose
        ? data
        : data.map((e) => ({
            ...e,
            matchedData: e.matchedData ? truncate(e.matchedData, 150) : undefined,
          }));

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
