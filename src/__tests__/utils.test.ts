import { describe, it, expect } from "vitest";
import { truncate } from "../tools/utils.js";

describe("truncate", () => {
  it("returns short strings unchanged", () => {
    expect(truncate("hello", 10)).toBe("hello");
  });

  it("returns string unchanged at exact max length", () => {
    expect(truncate("12345", 5)).toBe("12345");
  });

  it("truncates long strings with char count", () => {
    const result = truncate("abcdefghij", 5);
    expect(result).toBe("abcde... (5 chars truncated)");
  });

  it("handles empty string", () => {
    expect(truncate("", 10)).toBe("");
  });
});
