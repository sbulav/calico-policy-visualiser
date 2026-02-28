import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { PolicyNodeData } from '../../../types/graph';

type PolicyNodeComponentProps = NodeProps & { data: PolicyNodeData };

function PolicyNodeComponent({ data }: PolicyNodeComponentProps) {
  const isGlobal = data.kind === 'GlobalNetworkPolicy';
  const isCalico = data.policySource === 'calico';

  return (
    <div className="relative min-w-[280px] max-w-[360px]">
      <Handle
        type="target"
        position={Position.Left}
        id="left"
        className="!w-3 !h-3 !bg-indigo-400 !border-2 !border-indigo-600"
      />

      <div className="rounded-xl border-2 border-indigo-500/60 bg-slate-800/90 shadow-lg shadow-indigo-500/10 backdrop-blur-sm overflow-hidden">
        {/* Header */}
        <div className="bg-indigo-500/20 px-4 py-2 border-b border-indigo-500/30">
          <div className="flex items-center gap-2">
            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${
              isGlobal
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                : 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
            }`}>
              {isGlobal ? 'Global' : 'Namespaced'}
            </span>
            <span className="text-[10px] text-slate-400 font-mono">
              {isCalico ? `tier: ${data.tier}${data.order !== undefined ? ` | order: ${data.order}` : ''}` : 'k8s networking.k8s.io/v1'}
            </span>
          </div>
        </div>

        {/* Body */}
        <div className="px-4 py-3 space-y-2">
          {/* Policy Name */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Policy</div>
            <div className="text-sm font-semibold text-slate-100 break-all leading-tight mt-0.5">
              {data.name}
            </div>
          </div>

          {/* Namespace */}
          {data.namespace && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Namespace</div>
              <div className="text-xs font-mono text-cyan-300 mt-0.5">{data.namespace}</div>
            </div>
          )}

          {/* Namespace Selector (for GNP) */}
          {data.namespaceSelector && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Namespace Selector</div>
              <div className="text-[11px] font-mono text-amber-300 mt-0.5 break-all leading-snug bg-slate-900/50 rounded px-2 py-1">
                {data.namespaceSelector.length > 80
                  ? data.namespaceSelector.substring(0, 80) + '...'
                  : data.namespaceSelector}
              </div>
            </div>
          )}

          {/* Selector */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Selector</div>
            <div className="text-[11px] font-mono text-emerald-300 mt-0.5 break-all leading-snug bg-slate-900/50 rounded px-2 py-1">
              {data.selector}
            </div>
          </div>

          {/* Service Account Selector */}
          {data.serviceAccountSelector && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Service Account Selector</div>
              <div className="text-[11px] font-mono text-cyan-300 mt-0.5 break-all leading-snug bg-slate-900/50 rounded px-2 py-1">
                {data.serviceAccountSelector.length > 80
                  ? data.serviceAccountSelector.substring(0, 80) + '...'
                  : data.serviceAccountSelector}
              </div>
            </div>
          )}

          {/* Policy-level flags (preDNAT, applyOnForward, doNotTrack) */}
          {(data.preDNAT || data.applyOnForward || data.doNotTrack) && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {data.preDNAT && (
                <div className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-lg bg-violet-500/10 text-violet-300 border border-violet-500/30">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                  preDNAT
                </div>
              )}
              {data.applyOnForward && (
                <div className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-lg bg-teal-500/10 text-teal-300 border border-teal-500/30">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                  </svg>
                  applyOnForward
                </div>
              )}
              {data.doNotTrack && (
                <div className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/30">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                  </svg>
                  doNotTrack
                </div>
              )}
            </div>
          )}

          {/* Defaults — show effective default (accounts for catch-all rules) */}
          <div className="flex gap-2 pt-1">
            <div className={`flex-1 text-center text-[10px] font-bold uppercase tracking-wider px-2 py-1.5 rounded-lg border ${
              data.effectiveIngressDefault === 'deny'
                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                : 'bg-green-500/10 text-green-400 border-green-500/30'
            }`}>
              {`Ingress Default ${data.effectiveIngressDefault === 'deny' ? 'Deny' : 'Allow'}`}
            </div>
            <div className={`flex-1 text-center text-[10px] font-bold uppercase tracking-wider px-2 py-1.5 rounded-lg border ${
              data.effectiveEgressDefault === 'deny'
                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                : 'bg-green-500/10 text-green-400 border-green-500/30'
            }`}>
              {`Egress Default ${data.effectiveEgressDefault === 'deny' ? 'Deny' : 'Allow'}`}
            </div>
          </div>
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        id="right"
        className="!w-3 !h-3 !bg-indigo-400 !border-2 !border-indigo-600"
      />
    </div>
  );
}

export default memo(PolicyNodeComponent);
