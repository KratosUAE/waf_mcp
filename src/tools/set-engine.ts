import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const setEngineSchema = z.object({
  mode: z.enum(["On", "Off", "DetectionOnly"]).describe("WAF engine mode: On (blocking), Off (disabled), DetectionOnly (log only)"),
});

export function setEngineHandler(waf: WAFManager) {
  return async (args: z.infer<typeof setEngineSchema>) => {
    try {
      const result = await waf.setEngine(args.mode);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
