export type WAFEngine = "On" | "Off" | "DetectionOnly";

export interface WAFStatus {
  container: string;
  healthy: boolean;
  engine: WAFEngine;
  rulesLoaded: string;
  paranoiaLevel: number;
  blockingParanoia: number;
}

export interface WAFRuleMatch {
  id: string;
  message: string;
  severity: string;
  matchedData?: string;
}

export interface WAFEvent {
  index: number;
  timestamp: string;
  method: string;
  uri: string;
  sourceIp: string;
  httpCode: number;
  rules: WAFRuleMatch[];
  // Full data preserved for detail view
  _raw?: Record<string, unknown>;
}

export interface WAFOverview {
  totalEvents: number;
  uniqueIPs: number;
  uniqueRules: number;
  eventsLastHour: number;
}

export interface WAFTopIP {
  ip: string;
  count: number;
  geo: string | null;
  lastSeen: string;
}

export interface WAFTopRule {
  ruleId: string;
  count: number;
  severity: string;
  message: string;
}

export interface WAFFPCandidate {
  ruleId: string;
  count: number;
  message: string;
}

export interface WAFEventSummary {
  timestamp: string;
  method: string;
  uri: string;
  httpCode: number;
  rules: WAFRuleMatch[];
}

export interface WAFEventByRule {
  timestamp: string;
  ip: string;
  method: string;
  uri: string;
  httpCode: number;
  matchedData: string;
}

export interface WAFEventDetail {
  index: number;
  timestamp: string;
  sourceIp: string;
  method: string;
  uri: string;
  httpCode: number;
  requestHeaders: Record<string, string>;
  requestBody: string;
  rules: WAFRuleMatch[];
}

export interface IPInfo {
  city: string;
  country: string;
  org: string;
}

export interface CommandResult {
  success: boolean;
  output: string;
}
