import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const enableRuleSchema = z.object({
  ruleId: z.string().regex(/^\d+$/, "Rule ID must be numeric (e.g. '942140')")
    .describe("ModSecurity rule ID to re-enable (e.g. '942140')"),
});

export function enableRuleHandler(waf: WAFManager) {
  return async (args: z.infer<typeof enableRuleSchema>) => {
    try {
      const result = await waf.enableRule(args.ruleId);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
