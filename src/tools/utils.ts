export function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + `... (${s.length - max} chars truncated)`;
}

/** Strict IPv4 with optional CIDR /0-32 */
export const ipPattern = /^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\/([0-9]|[1-2]\d|3[0-2]))?$/;
