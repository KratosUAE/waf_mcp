import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const topIPsSchema = z.object({
  count: z.number().optional().default(10).describe("Number of top IPs to return (default 10)"),
});

export function topIPsHandler(waf: WAFManager) {
  return async (args: z.infer<typeof topIPsSchema>) => {
    try {
      const data = await waf.getTopIPs(args.count);
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
