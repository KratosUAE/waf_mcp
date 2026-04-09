import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { homedir } from "node:os";
import { logger } from "./logger.js";

export interface WAFConfig {
  composeDir: string;
  containerPattern: string;
  domain: string;
  exclusionsFile: string;
  composeFile: string;
  ipinfoToken: string | undefined;
  logsSince: string;
}

function loadIpinfoToken(): string | undefined {
  if (process.env.IPINFO_TOKEN) {
    return process.env.IPINFO_TOKEN;
  }
  const envPath = resolve(homedir(), ".aux", ".env");
  if (existsSync(envPath)) {
    try {
      const content = readFileSync(envPath, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("IPINFO_TOKEN=")) {
          const value = trimmed.slice("IPINFO_TOKEN=".length).replace(/^["']|["']$/g, "");
          if (value) return value;
        }
      }
    } catch (err) {
      logger.debug(`Failed to read ${envPath}: ${err}`);
    }
  }
  return undefined;
}

export function getConfig(): WAFConfig {
  const composeDir = process.env.WAF_COMPOSE_DIR;

  if (!composeDir) {
    logger.error("WAF_COMPOSE_DIR environment variable is required");
    process.exit(1);
  }

  if (!existsSync(composeDir)) {
    logger.error(`Compose directory does not exist: ${composeDir}`);
    process.exit(1);
  }

  const containerPattern = process.env.WAF_CONTAINER_PATTERN ?? "modsecurity";
  if (!/^[a-zA-Z0-9_.-]+$/.test(containerPattern)) {
    logger.error(`Invalid WAF_CONTAINER_PATTERN: must be alphanumeric/hyphens/dots/underscores`);
    process.exit(1);
  }

  const logsSince = process.env.WAF_LOGS_SINCE ?? "24h";
  if (!/^\d+[smhd]$/.test(logsSince)) {
    logger.error(`Invalid WAF_LOGS_SINCE: must match format like 24h, 30m, 7d`);
    process.exit(1);
  }

  const ipinfoToken = loadIpinfoToken();

  return {
    composeDir,
    containerPattern,
    domain: process.env.WAF_DOMAIN ?? "https://localhost",
    exclusionsFile: process.env.WAF_EXCLUSIONS_FILE ?? "modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
    composeFile: process.env.WAF_COMPOSE_FILE ?? "docker-compose.yml",
    ipinfoToken,
    logsSince,
  };
}
