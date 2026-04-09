import { z } from "zod";
import type WAFManager from "../waf-manager.js";
import { ipPattern } from "./utils.js";

export const denyIPSchema = z.object({
  ip: z.string().regex(ipPattern, "Must be a valid IPv4 address or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)")
    .describe("IP address to remove from whitelist"),
});

export function denyIPHandler(waf: WAFManager) {
  return async (args: z.infer<typeof denyIPSchema>) => {
    try {
      const result = await waf.denyIP(args.ip);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
