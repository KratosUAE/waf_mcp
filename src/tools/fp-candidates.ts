import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const fpCandidatesSchema = z.object({});

export function fpCandidatesHandler(waf: WAFManager) {
  return async (_args: z.infer<typeof fpCandidatesSchema>) => {
    try {
      const data = await waf.getFPCandidates();
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
