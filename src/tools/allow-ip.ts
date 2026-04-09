import { z } from "zod";
import type WAFManager from "../waf-manager.js";
import { ipPattern } from "./utils.js";

export const allowIPSchema = z.object({
  ip: z.string().regex(ipPattern, "Must be a valid IPv4 address or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)")
    .describe("IP address to whitelist (bypass WAF inspection)"),
});

export function allowIPHandler(waf: WAFManager) {
  return async (args: z.infer<typeof allowIPSchema>) => {
    try {
      const result = await waf.allowIP(args.ip);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
