import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const overviewSchema = z.object({});

export function overviewHandler(waf: WAFManager) {
  return async (_args: z.infer<typeof overviewSchema>) => {
    try {
      const data = await waf.getOverview();
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
