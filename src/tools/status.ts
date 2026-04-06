import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const statusSchema = z.object({});

export function statusHandler(waf: WAFManager) {
  return async (_args: z.infer<typeof statusSchema>) => {
    try {
      const data = await waf.getStatus();
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
