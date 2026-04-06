import { z } from "zod";
import type WAFManager from "../waf-manager.js";

export const testSchema = z.object({});

export function testHandler(waf: WAFManager) {
  return async (_args: z.infer<typeof testSchema>) => {
    try {
      const results = await waf.runTests();
      const passed = results.filter((r) => r.passed).length;
      const data = { passed, total: results.length, tests: results };
      return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }], isError: true };
    }
  };
}
