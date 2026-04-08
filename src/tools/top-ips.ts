import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const topIPsSchema = z.object({
  count: z.number().optional().default(10).describe("Number of top IPs to return (default 10)"),
  since: z.string().optional().default("24h").describe("Time window for log search (e.g. '1h', '24h', '7d'). Default: 24h"),
});

export function topIPsHandler(waf: WAFManager) {
  return async (args: z.infer<typeof topIPsSchema>) => {
    try {
      const data = await waf.getTopIPs(args.count, args.since);
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
