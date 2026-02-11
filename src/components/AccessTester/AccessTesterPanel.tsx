import { useState, useCallback, useMemo } from 'react';
import { usePolicyContext } from '../../context/usePolicyContext';
import { testAccess } from '../../lib/matcher/accessTester';
import type { TrafficSpec, AccessTestResult, EndpointType, RuleTraceEntry } from '../../types/matcher';
import type { SourceRange } from '../../types/graph';

type AccessTesterPanelProps = {
  onClose: () => void;
};

// ---- Label pair editor ----

type LabelEntry = { key: string; value: string };

function LabelEditor({
  labels,
  onChange,
  placeholder,
}: {
  labels: LabelEntry[];
  onChange: (labels: LabelEntry[]) => void;
  placeholder?: string;
}) {
  const handleAdd = useCallback(() => {
    onChange([...labels, { key: '', value: '' }]);
  }, [labels, onChange]);

  const handleRemove = useCallback((idx: number) => {
    onChange(labels.filter((_, i) => i !== idx));
  }, [labels, onChange]);

  const handleChange = useCallback((idx: number, field: 'key' | 'value', val: string) => {
    const updated = labels.map((l, i) => i === idx ? { ...l, [field]: val } : l);
    onChange(updated);
  }, [labels, onChange]);

  return (
    <div className="space-y-1.5">
      {labels.map((entry, idx) => (
        <div key={idx} className="flex items-center gap-1.5">
          <input
            type="text"
            value={entry.key}
            onChange={(e) => handleChange(idx, 'key', e.target.value)}
            placeholder="key"
            className="flex-1 min-w-0 text-xs px-2 py-1 rounded bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
          />
          <span className="text-slate-500 text-xs">=</span>
          <input
            type="text"
            value={entry.value}
            onChange={(e) => handleChange(idx, 'value', e.target.value)}
            placeholder="value"
            className="flex-1 min-w-0 text-xs px-2 py-1 rounded bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
          />
          <button
            onClick={() => handleRemove(idx)}
            className="text-slate-500 hover:text-red-400 transition-colors cursor-pointer p-0.5"
            title="Remove"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      ))}
      <button
        onClick={handleAdd}
        className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors cursor-pointer"
      >
        {placeholder ?? '+ Add label'}
      </button>
    </div>
  );
}

// ---- Verdict badge ----

function VerdictBadge({ verdict }: { verdict: AccessTestResult['verdict'] }) {
  const config = {
    allowed: { bg: 'bg-emerald-500/20', border: 'border-emerald-500/40', text: 'text-emerald-400', label: 'ALLOWED' },
    denied: { bg: 'bg-red-500/20', border: 'border-red-500/40', text: 'text-red-400', label: 'DENIED' },
    passed: { bg: 'bg-blue-500/20', border: 'border-blue-500/40', text: 'text-blue-400', label: 'PASSED TO NEXT TIER' },
    unknown: { bg: 'bg-amber-500/20', border: 'border-amber-500/40', text: 'text-amber-400', label: 'UNKNOWN' },
  }[verdict];

  return (
    <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border ${config.bg} ${config.border}`}>
      <span className={`text-sm font-bold ${config.text}`}>{config.label}</span>
    </div>
  );
}

// ---- Action badge (small, for trace entries) ----

function ActionBadge({ action }: { action: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    Allow: { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
    Deny: { bg: 'bg-red-500/20', text: 'text-red-400' },
    Log: { bg: 'bg-amber-500/20', text: 'text-amber-400' },
    Pass: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  };
  const c = config[action] ?? { bg: 'bg-slate-500/20', text: 'text-slate-400' };

  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold ${c.bg} ${c.text}`}>
      {action}
    </span>
  );
}

// ---- Trace entry row ----

function TraceRow({
  entry,
  onHover,
  onLeave,
}: {
  entry: RuleTraceEntry;
  onHover: (range: SourceRange | null) => void;
  onLeave: () => void;
}) {
  const handleMouseEnter = useCallback(() => {
    if (entry.sourceRange) onHover(entry.sourceRange);
  }, [entry.sourceRange, onHover]);

  const matchIcon = entry.matchResult.matches
    ? 'text-emerald-400'
    : entry.matchResult.indeterminate
      ? 'text-amber-400'
      : 'text-slate-500';

  const matchLabel = entry.matchResult.matches
    ? 'MATCH'
    : entry.matchResult.indeterminate
      ? 'MAYBE'
      : 'NO MATCH';

  return (
    <div
      className={`px-2.5 py-1.5 rounded-lg border text-xs ${
        entry.isDecisive
          ? 'border-indigo-500/40 bg-indigo-500/10'
          : 'border-slate-700/50 bg-slate-800/30'
      } hover:bg-slate-700/30 transition-colors cursor-default`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={onLeave}
    >
      <div className="flex items-center gap-2 mb-0.5">
        <span className="text-slate-500 font-mono text-[10px]">#{entry.ruleIndex + 1}</span>
        <ActionBadge action={entry.action} />
        <span className={`text-[10px] font-semibold ${matchIcon}`}>{matchLabel}</span>
        {entry.isDecisive && (
          <span className="text-[10px] font-semibold text-indigo-400 ml-auto">DECISIVE</span>
        )}
      </div>
      <p className="text-slate-400 text-[11px] leading-snug">{entry.matchResult.reason}</p>
    </div>
  );
}

// ---- Main panel ----

export default function AccessTesterPanel({ onClose }: AccessTesterPanelProps) {
  const { state, dispatch } = usePolicyContext();

  // Form state
  const [direction, setDirection] = useState<'ingress' | 'egress'>('ingress');
  const [endpointType, setEndpointType] = useState<EndpointType>('ip');
  const [ip, setIp] = useState('');
  const [podLabels, setPodLabels] = useState<LabelEntry[]>([{ key: '', value: '' }]);
  const [namespace, setNamespace] = useState('');
  const [namespaceLabels, setNamespaceLabels] = useState<LabelEntry[]>([]);
  const [serviceAccountName, setServiceAccountName] = useState('');
  const [serviceName, setServiceName] = useState('');
  const [serviceNamespace, setServiceNamespace] = useState('');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');

  // Result state
  const [result, setResult] = useState<AccessTestResult | null>(null);

  const handleReset = useCallback(() => {
    setDirection('ingress');
    setEndpointType('ip');
    setIp('');
    setPodLabels([{ key: '', value: '' }]);
    setNamespace('');
    setNamespaceLabels([]);
    setServiceAccountName('');
    setServiceName('');
    setServiceNamespace('');
    setProtocol('');
    setPort('');
    setResult(null);
    dispatch({ type: 'HIGHLIGHT_LINES', payload: null });
  }, [dispatch]);

  const buildSpec = useCallback((): TrafficSpec => {
    const spec: TrafficSpec = {};

    // Only include fields relevant to the selected endpoint type
    switch (endpointType) {
      case 'ip':
        if (ip.trim()) spec.ip = ip.trim();
        break;
      case 'podLabels': {
        const validLabels = podLabels.filter(l => l.key.trim());
        if (validLabels.length > 0) {
          spec.labels = Object.fromEntries(validLabels.map(l => [l.key.trim(), l.value.trim()]));
        }
        if (namespace.trim()) spec.namespace = namespace.trim();
        {
          const validNsLabels = namespaceLabels.filter(l => l.key.trim());
          if (validNsLabels.length > 0) {
            spec.namespaceLabels = Object.fromEntries(validNsLabels.map(l => [l.key.trim(), l.value.trim()]));
          }
        }
        break;
      }
      case 'namespace':
        if (namespace.trim()) spec.namespace = namespace.trim();
        {
          const validNsLabels = namespaceLabels.filter(l => l.key.trim());
          if (validNsLabels.length > 0) {
            spec.namespaceLabels = Object.fromEntries(validNsLabels.map(l => [l.key.trim(), l.value.trim()]));
          }
        }
        break;
      case 'serviceAccount':
        if (serviceAccountName.trim()) spec.serviceAccountName = serviceAccountName.trim();
        if (namespace.trim()) spec.namespace = namespace.trim();
        break;
      case 'service':
        if (serviceName.trim()) spec.serviceName = serviceName.trim();
        if (serviceNamespace.trim()) spec.serviceNamespace = serviceNamespace.trim();
        break;
    }

    // Protocol and port are always included (shown on all tabs)
    if (protocol) spec.protocol = protocol;
    if (port.trim()) {
      const n = Number(port.trim());
      if (!Number.isNaN(n) && n > 0 && n <= 65535) spec.port = n;
    }

    return spec;
  }, [endpointType, ip, podLabels, namespace, namespaceLabels, serviceAccountName, serviceName, serviceNamespace, protocol, port]);

  const handleTest = useCallback(() => {
    if (!state.policy) return;
    const spec = buildSpec();
    const res = testAccess(state.policy, direction, spec, state.ruleLineRanges);
    setResult(res);
  }, [state.policy, state.ruleLineRanges, direction, buildSpec]);

  const handleHighlight = useCallback((range: SourceRange | null) => {
    dispatch({ type: 'HIGHLIGHT_LINES', payload: range });
  }, [dispatch]);

  const handleClearHighlight = useCallback(() => {
    dispatch({ type: 'HIGHLIGHT_LINES', payload: null });
  }, [dispatch]);

  // Determine if directions are available based on policy types
  const policyTypes = useMemo(() => state.policy?.types ?? [], [state.policy]);
  const hasIngress = policyTypes.includes('Ingress');
  const hasEgress = policyTypes.includes('Egress');

  return (
    <div className="h-full flex flex-col bg-slate-850 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 h-9 border-b border-slate-700/50 bg-slate-800/50 shrink-0">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">Access Tester</span>
        </div>
        <button
          onClick={onClose}
          className="text-slate-500 hover:text-slate-300 transition-colors cursor-pointer p-0.5 rounded hover:bg-slate-700/50"
          aria-label="Close panel"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {/* Disclaimer */}
        <div className="text-[10px] text-amber-400/70 bg-amber-500/5 border border-amber-500/20 rounded-lg px-2.5 py-1.5 leading-snug">
          This is a best-effort emulation, not a real Calico policy engine. It evaluates a single
          policy in isolation. Real Calico evaluates all policies across tiers. Do not use for
          production security decisions.
        </div>

        {!state.policy ? (
          <div className="text-xs text-slate-500 text-center py-8">
            Load a policy first to test access
          </div>
        ) : (
          <>
            {/* Direction toggle */}
            <div>
              <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                Traffic Direction
              </label>
              <div className="flex gap-1">
                <button
                  onClick={() => { setDirection('ingress'); setResult(null); }}
                  className={`flex-1 text-xs py-1.5 rounded-lg border transition-colors cursor-pointer ${
                    direction === 'ingress'
                      ? 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
                  }`}
                >
                  Ingress {!hasIngress && <span className="text-[9px] text-slate-500">(unmanaged)</span>}
                </button>
                <button
                  onClick={() => { setDirection('egress'); setResult(null); }}
                  className={`flex-1 text-xs py-1.5 rounded-lg border transition-colors cursor-pointer ${
                    direction === 'egress'
                      ? 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
                  }`}
                >
                  Egress {!hasEgress && <span className="text-[9px] text-slate-500">(unmanaged)</span>}
                </button>
              </div>
            </div>

            {/* Endpoint type selector */}
            <div>
              <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                {direction === 'ingress' ? 'Source' : 'Destination'} Type
              </label>
              <div className="grid grid-cols-2 gap-1">
                {[
                  { type: 'ip' as EndpointType, label: 'IP Address' },
                  { type: 'podLabels' as EndpointType, label: 'Pod Labels' },
                  { type: 'namespace' as EndpointType, label: 'Namespace' },
                  { type: 'serviceAccount' as EndpointType, label: 'ServiceAccount' },
                  { type: 'service' as EndpointType, label: 'Service' },
                ].map(({ type, label }) => (
                  <button
                    key={type}
                    onClick={() => { setEndpointType(type); setResult(null); }}
                    className={`text-xs py-1.5 rounded-lg border transition-colors cursor-pointer ${
                      endpointType === type
                        ? 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Dynamic form fields */}
            <div className="space-y-2">
              {endpointType === 'ip' && (
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                    IP Address
                  </label>
                  <input
                    type="text"
                    value={ip}
                    onChange={(e) => { setIp(e.target.value); setResult(null); }}
                    placeholder="e.g. 10.0.1.5 or 8.8.8.8"
                    className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                  />
                </div>
              )}

              {endpointType === 'podLabels' && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Pod Labels
                    </label>
                    <LabelEditor labels={podLabels} onChange={(l) => { setPodLabels(l); setResult(null); }} />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Namespace Name <span className="normal-case tracking-normal font-normal text-slate-600">(opt., for namespaceSelector)</span>
                    </label>
                    <input
                      type="text"
                      value={namespace}
                      onChange={(e) => { setNamespace(e.target.value); setResult(null); }}
                      placeholder="e.g. database"
                      className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Namespace Labels <span className="normal-case tracking-normal font-normal text-slate-600">(opt., overrides name)</span>
                    </label>
                    <LabelEditor labels={namespaceLabels} onChange={(l) => { setNamespaceLabels(l); setResult(null); }} placeholder="+ Add namespace label" />
                  </div>
                </div>
              )}

              {endpointType === 'namespace' && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Namespace Name
                    </label>
                    <input
                      type="text"
                      value={namespace}
                      onChange={(e) => { setNamespace(e.target.value); setResult(null); }}
                      placeholder="e.g. backend"
                      className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Namespace Labels <span className="normal-case tracking-normal font-normal text-slate-600">(optional)</span>
                    </label>
                    <LabelEditor labels={namespaceLabels} onChange={(l) => { setNamespaceLabels(l); setResult(null); }} placeholder="+ Add namespace label" />
                  </div>
                </div>
              )}

              {endpointType === 'serviceAccount' && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      ServiceAccount Name
                    </label>
                    <input
                      type="text"
                      value={serviceAccountName}
                      onChange={(e) => { setServiceAccountName(e.target.value); setResult(null); }}
                      placeholder="e.g. backend-api"
                      className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Namespace <span className="normal-case tracking-normal font-normal text-slate-600">(optional, for scoped SA matching)</span>
                    </label>
                    <input
                      type="text"
                      value={namespace}
                      onChange={(e) => { setNamespace(e.target.value); setResult(null); }}
                      placeholder="e.g. default"
                      className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                    />
                  </div>
                </div>
              )}

              {endpointType === 'service' && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Service Name
                    </label>
                    <input
                      type="text"
                      value={serviceName}
                      onChange={(e) => { setServiceName(e.target.value); setResult(null); }}
                      placeholder="e.g. kube-dns"
                      className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                      Service Namespace
                    </label>
                    <input
                      type="text"
                      value={serviceNamespace}
                      onChange={(e) => { setServiceNamespace(e.target.value); setResult(null); }}
                      placeholder="e.g. kube-system"
                      className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                    />
                  </div>
                </div>
              )}

              {/* Protocol and Port — always shown */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                    Protocol <span className="normal-case tracking-normal font-normal text-slate-600">(opt.)</span>
                  </label>
                  <select
                    value={protocol}
                    onChange={(e) => { setProtocol(e.target.value); setResult(null); }}
                    className="w-full text-xs px-2 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none cursor-pointer"
                  >
                    <option value="">Any</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="SCTP">SCTP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 block">
                    Port <span className="normal-case tracking-normal font-normal text-slate-600">(opt.)</span>
                  </label>
                  <input
                    type="text"
                    value={port}
                    onChange={(e) => { setPort(e.target.value); setResult(null); }}
                    placeholder="e.g. 443"
                    className="w-full text-xs px-2.5 py-1.5 rounded-lg bg-slate-700/80 text-slate-200 border border-slate-600 focus:border-indigo-500 focus:outline-none placeholder:text-slate-500"
                  />
                </div>
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex gap-2">
              <button
                onClick={handleTest}
                className="flex-1 text-xs py-2 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-white font-semibold transition-colors cursor-pointer"
              >
                Check Access
              </button>
              <button
                onClick={handleReset}
                className="text-xs px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 font-semibold border border-slate-600 transition-colors cursor-pointer"
              >
                Reset
              </button>
            </div>

            {/* Results */}
            {result && (
              <div className="space-y-2.5 pt-1">
                {/* Verdict */}
                <div className="flex items-center justify-between">
                  <VerdictBadge verdict={result.verdict} />
                  {result.appliedDefault && (
                    <span className="text-[10px] text-slate-500">default applied</span>
                  )}
                </div>
                <p className="text-xs text-slate-300 leading-snug">{result.reason}</p>

                {/* Rule trace */}
                {result.trace.length > 0 && (
                  <div>
                    <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1.5">
                      Rule Evaluation Trace
                    </h4>
                    <div className="space-y-1">
                      {result.trace.map((entry) => (
                        <TraceRow
                          key={entry.ruleIndex}
                          entry={entry}
                          onHover={handleHighlight}
                          onLeave={handleClearHighlight}
                        />
                      ))}
                    </div>
                    {result.appliedDefault && (
                      <div className="px-2.5 py-1.5 mt-1 rounded-lg border border-slate-700/50 bg-slate-800/30 text-xs text-slate-400">
                        No rule matched — {result.verdict === 'allowed' ? 'implicit allow' : 'implicit deny'} applied
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
