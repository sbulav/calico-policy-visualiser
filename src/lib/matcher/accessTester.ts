/**
 * Access tester engine — walks Calico policy rules in evaluation order
 * and produces a verdict with full rule-by-rule trace.
 *
 * DISCLAIMER: This is a best-effort emulation of Calico's policy evaluation
 * for educational and visualization purposes. It does NOT replicate the real
 * Calico data-plane (eBPF / iptables). Key limitations:
 *
 *  - Only evaluates a single policy. Real Calico evaluates ALL policies across
 *    tiers in priority order. Cross-policy interactions are not modeled.
 *  - Selector matching is approximate (see selectorParser.ts disclaimer).
 *  - Named ports, services, and SA label selectors are reported as indeterminate.
 *  - The `Pass` action reports "would pass to next tier" but cannot resolve the
 *    final verdict since we don't have the full tier chain.
 *
 * Do not use this to make production security decisions.
 */

import type { ResolvedPolicy } from '../../types/calico';
import type { TrafficSpec, AccessTestResult, RuleTraceEntry } from '../../types/matcher';
import type { RuleLineRanges } from '../parser/yamlLineMapper';
import { matchRule } from './ruleMatcher';

/**
 * Test traffic against a policy and return a verdict with full trace.
 *
 * Calico evaluates rules top-to-bottom (first match wins for Allow/Deny).
 * Log rules are transparent (they log but don't decide). Pass delegates
 * to the next tier (we can only report it, not resolve it).
 */
export function testAccess(
  policy: ResolvedPolicy,
  direction: 'ingress' | 'egress',
  spec: TrafficSpec,
  ruleLineRanges?: RuleLineRanges | null,
): AccessTestResult {
  const rules = direction === 'ingress' ? policy.ingressRules : policy.egressRules;
  const baseDefault = direction === 'ingress' ? policy.ingressDefault : policy.egressDefault;
  const lineRanges = ruleLineRanges
    ? (direction === 'ingress' ? ruleLineRanges.ingress : ruleLineRanges.egress)
    : undefined;

  const trace: RuleTraceEntry[] = [];

  // Check if this direction is even managed by the policy
  const directionType = direction === 'ingress' ? 'Ingress' : 'Egress';
  if (!policy.types.includes(directionType as 'Ingress' | 'Egress')) {
    return {
      verdict: 'allowed',
      reason: `Policy does not manage ${direction} traffic — all ${direction} is implicitly allowed`,
      trace: [],
      decisiveRuleIndex: null,
      appliedDefault: true,
    };
  }

  // Walk rules in Calico evaluation order (first-match-wins)
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    const matchResult = matchRule(rule, direction, spec);
    const sourceRange = lineRanges && lineRanges[i]
      ? { startLine: lineRanges[i].startLine, endLine: lineRanges[i].endLine }
      : undefined;

    const entry: RuleTraceEntry = {
      ruleIndex: i,
      rule,
      action: rule.action,
      matchResult,
      isDecisive: false,
      sourceRange,
    };

    if (matchResult.matches) {
      // The rule matched — check its action
      switch (rule.action) {
        case 'Allow':
          entry.isDecisive = true;
          trace.push(entry);
          return {
            verdict: 'allowed',
            reason: `Allowed by rule #${i + 1}: ${matchResult.reason}`,
            trace,
            decisiveRuleIndex: i,
            appliedDefault: false,
          };
        case 'Deny':
          entry.isDecisive = true;
          trace.push(entry);
          return {
            verdict: 'denied',
            reason: `Denied by rule #${i + 1}: ${matchResult.reason}`,
            trace,
            decisiveRuleIndex: i,
            appliedDefault: false,
          };
        case 'Log':
          // Log is transparent — record it but continue
          trace.push(entry);
          continue;
        case 'Pass':
          entry.isDecisive = true;
          trace.push(entry);
          return {
            verdict: 'passed',
            reason: `Passed to next tier by rule #${i + 1} (verdict depends on subsequent tiers)`,
            trace,
            decisiveRuleIndex: i,
            appliedDefault: false,
          };
      }
    } else if (matchResult.indeterminate) {
      // Indeterminate — the rule might match but we don't have enough info.
      // Continue to next rule but mark it in the trace.
      trace.push(entry);
    } else {
      // Definite no-match — record and continue
      trace.push(entry);
    }
  }

  // No rule matched — apply the default
  const effectiveDefault = baseDefault === 'allow' ? 'allowed' : 'denied';
  const defaultLabel = baseDefault === 'allow'
    ? 'This direction is not explicitly managed — traffic is allowed by default'
    : 'No rule matched — traffic is denied by implicit Calico default';

  return {
    verdict: effectiveDefault as 'allowed' | 'denied',
    reason: defaultLabel,
    trace,
    decisiveRuleIndex: null,
    appliedDefault: true,
  };
}
