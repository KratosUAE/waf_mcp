import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const disableRuleSchema = z.object({
  ruleId: z.string().regex(/^\d+$/, "Rule ID must be numeric (e.g. '942140')")
    .describe("ModSecurity rule ID to disable (e.g. '942140')"),
});

export function disableRuleHandler(waf: WAFManager) {
  return async (args: z.infer<typeof disableRuleSchema>) => {
    try {
      const result = await waf.disableRule(args.ruleId);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
