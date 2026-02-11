import type { RuleAction, Rule } from './calico';
import type { SourceRange } from './graph';

/**
 * Describes the traffic endpoint and characteristics to test against a policy.
 *
 * Users can specify as many or as few fields as they want.
 * Unspecified fields are treated as "any" — a rule that constrains a field
 * the user did not provide will report "indeterminate" rather than assuming
 * match or no-match.
 */
export interface TrafficSpec {
  // --- Endpoint identity ---
  ip?: string;                            // IPv4 address (e.g. "10.0.1.5")
  labels?: Record<string, string>;        // Pod labels
  namespace?: string;                     // Namespace name
  namespaceLabels?: Record<string, string>; // Namespace-level labels (for namespaceSelector matching)
  serviceAccountName?: string;            // ServiceAccount name
  serviceName?: string;                   // Kubernetes Service name
  serviceNamespace?: string;              // Kubernetes Service namespace

  // --- Traffic characteristics ---
  protocol?: string;                      // TCP, UDP, SCTP, ICMP, etc.
  port?: number;                          // Destination port number
}

/** Why a single field inside a rule matched or did not match */
export interface FieldMatchDetail {
  field: string;         // e.g. "nets", "selector", "ports"
  matched: boolean;
  reason: string;        // Human-readable explanation
  indeterminate?: boolean; // User didn't provide the data needed to evaluate
}

/** Result of evaluating a single rule against the traffic spec */
export interface RuleMatchResult {
  matches: boolean;
  /** True when the rule has constraints we cannot evaluate (missing user input) */
  indeterminate: boolean;
  /** Per-field breakdown */
  details: FieldMatchDetail[];
  /** One-line summary */
  reason: string;
}

/** A single entry in the evaluation trace (one per rule) */
export interface RuleTraceEntry {
  ruleIndex: number;
  rule: Rule;
  action: RuleAction;
  matchResult: RuleMatchResult;
  /** True if this rule determined the final verdict */
  isDecisive: boolean;
  /** YAML line range for highlighting */
  sourceRange?: SourceRange;
}

/** Final verdict of the access test */
export type AccessVerdict = 'allowed' | 'denied' | 'passed' | 'unknown';

/** Complete result of testing traffic against a policy */
export interface AccessTestResult {
  verdict: AccessVerdict;
  reason: string;
  trace: RuleTraceEntry[];
  /** Index of the rule that decided the verdict, or null if default applied */
  decisiveRuleIndex: number | null;
  /** True if no rule matched and the implicit/effective default was applied */
  appliedDefault: boolean;
}

/**
 * The endpoint type the user selected in the UI.
 * Determines which form fields are shown.
 */
export type EndpointType = 'ip' | 'podLabels' | 'namespace' | 'serviceAccount' | 'service';
