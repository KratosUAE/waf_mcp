import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const topRulesSchema = z.object({
  count: z.number().optional().default(10).describe("Number of top rules to return (default 10)"),
});

export function topRulesHandler(waf: WAFManager) {
  return async (args: z.infer<typeof topRulesSchema>) => {
    try {
      const data = await waf.getTopRules(args.count);
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
