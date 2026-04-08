import { z } from "zod";
import type WAFManager from "../waf-manager.js";
import { truncate } from "./utils.js";

export const eventDetailSchema = z.object({
  index: z.number().describe("Event index from a previous query result"),
  verbose: z.boolean().optional().default(false).describe("Return full body and matched data (default: truncated for readability)"),
  since: z.string().optional().default("24h").describe("Time window for log search (e.g. '1h', '24h', '7d'). Default: 24h"),
});

export function eventDetailHandler(waf: WAFManager) {
  return async (args: z.infer<typeof eventDetailSchema>) => {
    try {
      const data = await waf.getEventDetail(args.index, args.verbose, args.since);

      if (!args.verbose) {
        data.requestBody = truncate(data.requestBody || "", 500);
        data.rules = data.rules.map((r) => ({
          ...r,
          matchedData: r.matchedData ? truncate(r.matchedData, 200) : undefined,
        }));
      }

      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
