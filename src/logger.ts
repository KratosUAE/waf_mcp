const debugEnabled = !!process.env.WAF_DEBUG;

function timestamp(): string {
  return new Date().toISOString();
}

export const logger = {
  debug(msg: string): void {
    if (debugEnabled) {
      process.stderr.write(`[${timestamp()}] DEBUG: ${msg}\n`);
    }
  },

  info(msg: string): void {
    process.stderr.write(`[${timestamp()}] INFO: ${msg}\n`);
  },

  error(msg: string): void {
    process.stderr.write(`[${timestamp()}] ERROR: ${msg}\n`);
  },
};
