import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const setParanoiaSchema = z.object({
  level: z.number().min(1).max(4).describe("CRS paranoia level (1 = low, 4 = highest). Higher levels catch more attacks but increase false positives."),
});

export function setParanoiaHandler(waf: WAFManager) {
  return async (args: z.infer<typeof setParanoiaSchema>) => {
    try {
      const result = await waf.setParanoia(args.level);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
