import { memo, useCallback } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { RuleDetail, RuleNodeData, SourceRange } from '../../../types/graph';
import type { RuleAction } from '../../../types/calico';
import { usePolicyContext } from '../../../context/usePolicyContext';
import { isValidPort, isValidCidr } from '../../../lib/ipUtils';

type RuleNodeComponentProps = NodeProps & { data: RuleNodeData };

const MAX_VISIBLE_PORTS = 3;

function getCategoryIcon(category: string): string {
  switch (category) {
    case 'outsideCluster': return '\u{1F310}'; // globe
    case 'inNamespace': return '\u{1F4E6}'; // package
    case 'inCluster': return '\u{2601}'; // cloud
    default: return '\u{1F50C}'; // plug
  }
}

function getCategoryColors(category: string): { border: string; bg: string; headerBg: string; iconBg: string } {
  switch (category) {
    case 'outsideCluster':
      return {
        border: 'border-orange-500/50',
        bg: 'bg-slate-800/90',
        headerBg: 'bg-orange-500/15',
        iconBg: 'bg-orange-500/20',
      };
    case 'inNamespace':
      return {
        border: 'border-cyan-500/50',
        bg: 'bg-slate-800/90',
        headerBg: 'bg-cyan-500/15',
        iconBg: 'bg-cyan-500/20',
      };
    case 'inCluster':
      return {
        border: 'border-purple-500/50',
        bg: 'bg-slate-800/90',
        headerBg: 'bg-purple-500/15',
        iconBg: 'bg-purple-500/20',
      };
    default:
      return {
        border: 'border-slate-500/50',
        bg: 'bg-slate-800/90',
        headerBg: 'bg-slate-500/15',
        iconBg: 'bg-slate-500/20',
      };
  }
}

function getActionColors(action: RuleAction): { card: string; dot: string } {
  switch (action) {
    case 'Allow':
      return { card: 'bg-green-500/8 border-green-500/20 text-green-300', dot: 'bg-green-400' };
    case 'Deny':
      return { card: 'bg-red-500/8 border-red-500/20 text-red-300', dot: 'bg-red-400' };
    case 'Log':
      return { card: 'bg-amber-500/8 border-amber-500/20 text-amber-300', dot: 'bg-amber-400' };
    case 'Pass':
      return { card: 'bg-blue-500/8 border-blue-500/20 text-blue-300', dot: 'bg-blue-400' };
    default:
      return { card: 'bg-slate-500/8 border-slate-500/20 text-slate-300', dot: 'bg-slate-400' };
  }
}

/** Check whether a port string (as formatted by formatPort) represents a valid port. */
function isPortStringValid(portStr: string): boolean {
  // formatPort() converts numbers to strings, so try parsing back
  const asNum = Number(portStr);
  if (!Number.isNaN(asNum) && String(asNum) === portStr) {
    return isValidPort(asNum);
  }
  // String port — range "start:end" or named port
  return isValidPort(portStr);
}

/** Render a single port value, highlighted red if invalid. */
function PortValue({ port, baseClass }: { port: string; baseClass: string }) {
  const valid = isPortStringValid(port);
  if (valid) {
    return <span className={baseClass}>{port}</span>;
  }
  return (
    <span
      className="text-red-400 font-semibold underline decoration-wavy decoration-red-400/60"
      title={`Invalid port: ${port}`}
    >
      {port}
    </span>
  );
}

/** Render ports with overflow hint. Shows up to MAX_VISIBLE_PORTS, then * with tooltip. */
function PortsDisplay({ ports, highlight }: { ports: string[]; highlight?: boolean }) {
  if (ports.length === 0) return null;

  const baseClass = highlight ? 'text-orange-400 font-semibold' : 'opacity-75';

  if (ports.length <= MAX_VISIBLE_PORTS) {
    return (
      <span className="font-mono text-[10px]">
        <span className={baseClass}>:</span>
        {ports.map((p, i) => (
          <span key={i}>
            {i > 0 && <span className={baseClass}>, </span>}
            <PortValue port={p} baseClass={baseClass} />
          </span>
        ))}
      </span>
    );
  }

  const visible = ports.slice(0, MAX_VISIBLE_PORTS);
  const allPortsText = ports.join('\n');

  return (
    <span className="font-mono text-[10px]">
      <span className={baseClass}>:</span>
      {visible.map((p, i) => (
        <span key={i}>
          {i > 0 && <span className={baseClass}>, </span>}
          <PortValue port={p} baseClass={baseClass} />
        </span>
      ))}{' '}
      <span
        className="ports-hint text-[10px]"
        data-tooltip={allPortsText}
      >
        *
      </span>
    </span>
  );
}

/** Render a list of CIDRs inline, highlighting invalid ones in red. */
function CidrList({ cidrs, max }: { cidrs: string[]; max?: number }) {
  const limit = max ?? cidrs.length;
  const visible = cidrs.slice(0, limit);
  const overflow = cidrs.length - limit;
  return (
    <>
      {visible.map((cidr, i) => (
        <span key={i}>
          {i > 0 && ', '}
          {isValidCidr(cidr) ? (
            cidr
          ) : (
            <span
              className="text-red-400 font-semibold underline decoration-wavy decoration-red-400/60"
              title={`Invalid CIDR: ${cidr}`}
            >
              {cidr}
            </span>
          )}
        </span>
      ))}
      {overflow > 0 && ` +${overflow} more`}
    </>
  );
}

/** A single CIDR entry card for Outside Cluster rules */
function CidrEntryCard({ cidr, action, protocol, ports, notNets, notPorts, oppositeLabel, oppositePorts, oppositeSelector, oppositeNets, sourceRange, onHover }: {
  cidr: string;
  action: RuleAction;
  protocol?: string;
  ports?: string[];
  notNets?: string[];
  notPorts?: string[];
  oppositeLabel?: string | null;
  oppositePorts?: string[];
  oppositeSelector?: string;
  oppositeNets?: string[];
  sourceRange?: SourceRange;
  onHover?: (range: SourceRange | null) => void;
}) {
  const colors = getActionColors(action);
  return (
    <div
      className={`text-[11px] px-2.5 py-1.5 rounded-lg border ${colors.card}`}
      onMouseEnter={sourceRange && onHover ? () => onHover(sourceRange) : undefined}
      onMouseLeave={onHover ? () => onHover(null) : undefined}
    >
      {/* Top row: action dot + action label + CIDR ... protocol */}
      <div className="flex items-center gap-1.5">
        <span className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${colors.dot}`} />
        <span className="font-bold uppercase text-[10px]">{action}</span>
        {isValidCidr(cidr) ? (
          <span className="font-mono text-[10px] opacity-90 flex-1 truncate">{cidr}</span>
        ) : (
          <span
            className="font-mono text-[10px] text-red-400 font-semibold underline decoration-wavy decoration-red-400/60 flex-1 truncate"
            title={`Invalid CIDR: ${cidr}`}
          >
            {cidr}
          </span>
        )}
        {protocol && (
          <span className="font-mono text-[10px] text-orange-400 font-semibold shrink-0 ml-1">{protocol}</span>
        )}
      </div>

      {/* Bottom row: ports right-aligned, highlighted in orange */}
      {ports && ports.length > 0 && (
        <div className="flex justify-end mt-0.5">
          <PortsDisplay ports={ports} highlight />
        </div>
      )}

      {/* Opposite-side match criteria (dst: for ingress, src: for egress) */}
      {oppositeLabel && (oppositeNets || oppositeSelector || (oppositePorts && oppositePorts.length > 0)) && (
        <div className="font-mono text-[10px] text-amber-400/70 pl-3 leading-snug mt-0.5">
          {oppositeNets && oppositeNets.length > 0 && (
            <div className="truncate">
              {oppositeLabel}: <CidrList cidrs={oppositeNets} max={3} />
            </div>
          )}
          {oppositeSelector && (
            <div className="truncate">{oppositeLabel}: {oppositeSelector}</div>
          )}
          {oppositePorts && oppositePorts.length > 0 && (
            <div className="flex items-center gap-1">
              <span>{oppositeLabel}:</span>
              <PortsDisplay ports={oppositePorts} highlight />
            </div>
          )}
        </div>
      )}

      {/* Negative matches */}
      {notNets && notNets.length > 0 && (
        <div className="font-mono text-[10px] text-red-400/70 pl-3 leading-snug">
          NOT: <CidrList cidrs={notNets} />
        </div>
      )}
      {notPorts && notPorts.length > 0 && (
        <div className="font-mono text-[10px] text-red-400/70 pl-3 leading-snug">
          NOT ports: {notPorts.join(', ')}
        </div>
      )}
    </div>
  );
}

/** Default rule card used for non-CIDR rules and non-outsideCluster categories */
function DefaultRuleCard({ rule, onHover }: { rule: RuleDetail; onHover?: (range: SourceRange | null) => void }) {
  const colors = getActionColors(rule.action);

  // Determine opposite-side ports, selector, and nets
  const oppositePorts = rule.dstPorts ?? rule.srcPorts;
  const oppositeSelector = rule.dstSelector ?? rule.srcSelector;
  const oppositeNets = rule.dstNets ?? rule.srcNets;
  const oppositeLabel = rule.dstPorts || rule.dstSelector || rule.dstNets ? 'dst' : rule.srcPorts || rule.srcSelector || rule.srcNets ? 'src' : null;

  return (
    <div
      className={`text-[11px] px-2.5 py-1.5 rounded-lg border ${colors.card}`}
      onMouseEnter={rule.sourceRange && onHover ? () => onHover(rule.sourceRange!) : undefined}
      onMouseLeave={onHover ? () => onHover(null) : undefined}
    >
      {/* Top row: action dot + action label ... protocol (right-aligned, orange) */}
      <div className="flex items-center gap-1.5">
        <span className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${colors.dot}`} />
        <span className="font-bold uppercase text-[10px]">{rule.action}</span>
        <span className="flex-1" />
        {rule.protocol && (
          <span className="font-mono text-[10px] text-orange-400 font-semibold shrink-0">{rule.protocol}</span>
        )}
      </div>

      {/* Ports row (right-aligned, highlighted orange) */}
      {rule.ports && rule.ports.length > 0 && (
        <div className="flex justify-end mt-0.5">
          <PortsDisplay ports={rule.ports} highlight />
        </div>
      )}

      {/* CIDRs (fallback for outsideCluster rules without nets — e.g., open entity) */}
      {rule.nets && rule.nets.length > 0 && (
        <div className="font-mono text-[10px] opacity-70 pl-3 leading-snug">
          <CidrList cidrs={rule.nets} max={3} />
        </div>
      )}

      {/* Services */}
      {rule.services && (
        <div className="font-mono text-[10px] opacity-70 pl-3 leading-snug">
          svc: {rule.services.name} <span className="text-slate-500">({rule.services.namespace})</span>
        </div>
      )}

      {/* Service Accounts */}
      {rule.serviceAccounts && (
        <div className="font-mono text-[10px] text-cyan-400/70 pl-3 leading-snug">
          {rule.serviceAccounts.names && rule.serviceAccounts.names.map((name, j) => (
            <div key={j}>sa: {name}</div>
          ))}
          {rule.serviceAccounts.selector && (
            <div>sa selector: {rule.serviceAccounts.selector}</div>
          )}
        </div>
      )}

      {/* Selector */}
      {rule.selector && (
        <div className="font-mono text-[10px] opacity-70 pl-3 leading-snug truncate">
          {rule.selector}
        </div>
      )}

      {/* Namespace selector */}
      {rule.namespaceSelector && (
        <div className="font-mono text-[10px] opacity-70 pl-3 leading-snug truncate">
          ns: {rule.namespaceSelector}
        </div>
      )}

      {/* Opposite-side match criteria (dst: for ingress, src: for egress) */}
      {oppositeLabel && (oppositeNets || oppositeSelector || (oppositePorts && oppositePorts.length > 0)) && (
        <div className="font-mono text-[10px] text-amber-400/70 pl-3 leading-snug mt-0.5">
          {oppositeNets && oppositeNets.length > 0 && (
            <div className="truncate">
              {oppositeLabel}: <CidrList cidrs={oppositeNets} max={3} />
            </div>
          )}
          {oppositeSelector && (
            <div className="truncate">{oppositeLabel}: {oppositeSelector}</div>
          )}
          {oppositePorts && oppositePorts.length > 0 && (
            <div className="flex items-center gap-1">
              <span>{oppositeLabel}:</span>
              <PortsDisplay ports={oppositePorts} highlight />
            </div>
          )}
        </div>
      )}

      {/* Negative matches */}
      {rule.notNets && rule.notNets.length > 0 && (
        <div className="font-mono text-[10px] text-red-400/70 pl-3 leading-snug">
          NOT: <CidrList cidrs={rule.notNets} />
        </div>
      )}
      {rule.notPorts && rule.notPorts.length > 0 && (
        <div className="font-mono text-[10px] text-red-400/70 pl-3 leading-snug">
          NOT ports: {rule.notPorts.join(', ')}
        </div>
      )}
    </div>
  );
}

/** Expand outsideCluster rules: each CIDR in a rule.nets becomes its own card */
function renderOutsideClusterRules(rules: RuleDetail[], onHover?: (range: SourceRange | null) => void) {
  const entries: { key: string; cidr: string; rule: RuleDetail }[] = [];
  const nonCidrRules: { key: string; rule: RuleDetail }[] = [];

  rules.forEach((rule, ruleIdx) => {
    if (rule.nets && rule.nets.length > 0) {
      rule.nets.forEach((cidr, cidrIdx) => {
        entries.push({
          key: `${ruleIdx}-cidr-${cidrIdx}`,
          cidr,
          rule,
        });
      });
    } else {
      // Rule classified as outsideCluster but has no nets (e.g., open entity)
      nonCidrRules.push({ key: `${ruleIdx}-nonet`, rule });
    }
  });

  return (
    <>
      {entries.map(({ key, cidr, rule }) => {
        const oppositePorts = rule.dstPorts ?? rule.srcPorts;
        const oppositeSelector = rule.dstSelector ?? rule.srcSelector;
        const oppositeNets = rule.dstNets ?? rule.srcNets;
        const oppositeLabel = rule.dstPorts || rule.dstSelector || rule.dstNets ? 'dst' : rule.srcPorts || rule.srcSelector || rule.srcNets ? 'src' : null;
        return (
          <CidrEntryCard
            key={key}
            cidr={cidr}
            action={rule.action}
            protocol={rule.protocol}
            ports={rule.ports}
            notNets={rule.notNets}
            notPorts={rule.notPorts}
            oppositeLabel={oppositeLabel}
            oppositePorts={oppositePorts}
            oppositeSelector={oppositeSelector}
            oppositeNets={oppositeNets}
            sourceRange={rule.sourceRange}
            onHover={onHover}
          />
        );
      })}
      {nonCidrRules.map(({ key, rule }) => (
        <DefaultRuleCard key={key} rule={rule} onHover={onHover} />
      ))}
    </>
  );
}

function getUnmanagedPlaceholder(category: string): string {
  switch (category) {
    case 'outsideCluster': return 'Any Endpoint';
    case 'inNamespace': return 'Any pod';
    case 'inCluster': return 'Everything in the cluster';
    default: return 'All traffic';
  }
}

function RuleNodeComponent({ data }: RuleNodeComponentProps) {
  const { dispatch } = usePolicyContext();
  const colors = getCategoryColors(data.category);
  const icon = getCategoryIcon(data.category);
  const isIngress = data.direction === 'ingress';
  const { groups } = data;
  const isOutsideCluster = data.category === 'outsideCluster';

  const handleRuleHover = useCallback((range: SourceRange | null) => {
    dispatch({ type: 'HIGHLIGHT_LINES', payload: range });
  }, [dispatch]);

  return (
    <div className={`min-w-[240px] max-w-[320px]`}>
      {isIngress && (
        <Handle
          type="source"
          position={Position.Right}
          id="right"
          className="!w-3 !h-3 !bg-slate-400 !border-2 !border-slate-600"
        />
      )}
      {!isIngress && (
        <Handle
          type="target"
          position={Position.Left}
          id="left"
          className="!w-3 !h-3 !bg-slate-400 !border-2 !border-slate-600"
        />
      )}

      <div className={`rounded-xl border-2 ${colors.border} ${colors.bg} shadow-lg backdrop-blur-sm overflow-hidden`}>
        {/* Header */}
        <div className={`${colors.headerBg} px-4 py-2 border-b ${colors.border}`}>
          <div className="flex items-center gap-2">
            <span className={`text-lg ${colors.iconBg} rounded-lg p-1 leading-none`}>{icon}</span>
            <div>
              <div className="text-sm font-semibold text-slate-100">{data.label}</div>
              <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                {isIngress ? 'Ingress Source' : 'Egress Destination'}
              </div>
            </div>
          </div>
        </div>

        {/* Rules */}
        <div className="px-3 py-2 space-y-1.5">
          {groups.rules.length === 0 && data.unmanaged && (
            <div className="text-[11px] px-2.5 py-2 text-center text-green-400/80 font-semibold">
              {getUnmanagedPlaceholder(data.category)}
            </div>
          )}
          {groups.rules.length === 0 && !data.unmanaged && (
            <div className="text-[11px] px-2.5 py-2 text-center text-slate-500 italic">
              No rules
            </div>
          )}

          {/* Outside Cluster: expand each CIDR into its own card */}
          {isOutsideCluster && groups.rules.length > 0 && renderOutsideClusterRules(groups.rules, handleRuleHover)}

          {/* Other categories: render default cards */}
          {!isOutsideCluster && groups.rules.map((rule, i) => (
            <DefaultRuleCard key={i} rule={rule} onHover={handleRuleHover} />
          ))}

          {/* Inferred statuses (Any pod, DNS, Cluster-wide) */}
          {groups.inferredStatuses && groups.inferredStatuses.length > 0 && (
            <>
              <div className="border-t border-slate-600/40 my-1.5" />
              {groups.inferredStatuses.map((status, i) => {
                const cardClass = status.state === 'allowed'
                  ? 'bg-green-500/5 border-green-500/15 text-green-400/80'
                  : status.state === 'denied'
                    ? 'bg-red-500/5 border-red-500/15 text-red-400/80'
                    : 'bg-orange-500/5 border-orange-500/15 text-orange-400/80';
                const icon = status.state === 'allowed' ? '\u2705' : status.state === 'denied' ? '\u274C' : '\u{1F7E0}';
                const labelClass = status.state === 'allowed'
                  ? 'text-green-400/70'
                  : status.state === 'denied'
                    ? 'text-red-400/70'
                    : 'text-orange-400/70';
                const stateLabel = status.state === 'allowed' ? 'allowed' : status.state === 'denied' ? 'denied' : 'likely';

                return (
                  <div
                    key={i}
                    className={`text-[11px] px-2.5 py-1.5 rounded-lg border ${cardClass}`}
                    title={status.reason}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px]">{icon}</span>
                      <span className="font-semibold text-[10px]">{status.label}</span>
                      <span className={`text-[10px] font-mono ${labelClass}`}>
                        {stateLabel}
                      </span>
                    </div>
                    <div className="text-[9px] opacity-60 pl-5 leading-snug mt-0.5">
                      {status.reason}
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(RuleNodeComponent);
