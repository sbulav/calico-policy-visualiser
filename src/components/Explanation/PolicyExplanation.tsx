import { useMemo } from 'react';

import { usePolicyState } from '../../context/usePolicyContext';
import { explainPolicy, type ExplanationSection } from '../../lib/explain/policyExplainer';

function SectionIcon({ type }: { type: ExplanationSection['type'] }) {
  switch (type) {
    case 'info':
      return (
        <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
    case 'ingress':
      return (
        <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
      );
    case 'egress':
      return (
        <svg className="w-4 h-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
      );
    case 'warning':
      return (
        <svg className="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      );
  }
}

function getSectionBorder(type: ExplanationSection['type']): string {
  switch (type) {
    case 'info': return 'border-l-indigo-500';
    case 'ingress': return 'border-l-cyan-500';
    case 'egress': return 'border-l-orange-500';
    case 'warning': return 'border-l-amber-500';
  }
}

export default function PolicyExplanation() {
  const { policy } = usePolicyState();

  // Memoized so unrelated state changes (hover highlights, keystrokes)
  // don't re-run the explanation walk.
  const result = useMemo(() => {
    if (!policy) {
      return null;
    }
    try {
      return { sections: explainPolicy(policy), error: null };
    } catch (err) {
      console.error('explainPolicy failed:', err);
      return { sections: null, error: err instanceof Error ? err.message : 'Unknown error' };
    }
  }, [policy]);

  if (!result) {
    return null;
  }

  if (result.error !== null || !result.sections) {
    return (
      <div className="h-full flex items-center justify-center p-4 bg-slate-900/50">
        <p className="text-xs text-red-400">
          Failed to generate explanation: {result.error}
        </p>
      </div>
    );
  }

  const sections: ExplanationSection[] = result.sections;

  return (
    <div className="h-full overflow-y-auto p-4 bg-slate-900/50">
      <div className="flex items-center gap-2 mb-3">
        <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <h3 className="text-sm font-semibold text-slate-200">Policy Explanation</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {sections.map((section, i) => (
          <div
            key={i}
            className={`bg-slate-800/60 rounded-lg border border-slate-700/50 border-l-2 ${getSectionBorder(section.type)} overflow-hidden`}
          >
            <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-700/50 bg-slate-800/40">
              <SectionIcon type={section.type} />
              <span className="text-xs font-semibold text-slate-300">{section.title}</span>
            </div>
            <div className="px-3 py-2 space-y-1">
              {section.items.map((item, j) => (
                item === '---' ? (
                  <div key={j} className="border-t border-slate-600/50 my-1.5" />
                ) : (
                  <div key={j} className="text-[11px] text-slate-400 leading-relaxed">
                    {item.startsWith('[+]') ? (
                      <span>
                        <span className="text-green-400 font-semibold">[ALLOW]</span>
                        {item.substring(3)}
                      </span>
                    ) : item.startsWith('[x]') ? (
                      <span>
                        <span className="text-red-400 font-semibold">[DENY]</span>
                        {item.substring(3)}
                      </span>
                    ) : item.startsWith('[?]') ? (
                      <span>
                        <span className="text-orange-400 font-semibold">[LIKELY]</span>
                        {item.substring(3)}
                      </span>
                    ) : item.startsWith('[!]') ? (
                      <span>
                        <span className="text-amber-400 font-semibold">[LOG]</span>
                        {item.substring(3)}
                      </span>
                    ) : item.startsWith('[~]') ? (
                      <span>
                        <span className="text-blue-400 font-semibold">[PASS]</span>
                        {item.substring(3)}
                      </span>
                    ) : (
                      item
                    )}
                  </div>
                )
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
