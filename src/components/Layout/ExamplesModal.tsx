import { useCallback, useEffect, useRef } from 'react';
import { SAMPLE_CATEGORIES, SAMPLE_POLICIES, type SamplePolicy } from '../../samples';

const CATEGORY_ICONS: Record<string, string> = {
  'Baseline / Zero Trust': '\u{1F6E1}\uFE0F',
  'Pod & Namespace Scoping': '\u{1F4E6}',
  'Database & Stateful Workloads': '\u{1F5C4}\uFE0F',
  'Gateway API & Ingress Controller': '\u{1F6AA}',
  'Egress Control & Internet Access': '\u{1F310}',
  'Port & Protocol Restrictions': '\u{1F50C}',
  'ServiceAccount-Aware Policies (Calico-Specific)': '\u{1F464}',
  'GlobalNetworkPolicy & Cluster Protection': '\u{1F512}',
  'Production Reference Architectures': '\u{1F3D7}\uFE0F',
};

type ExamplesModalProps = {
  open: boolean;
  onClose: () => void;
  onSelect: (policy: SamplePolicy) => void;
};

export default function ExamplesModal({ open, onClose, onSelect }: ExamplesModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (open && !dialog.open) {
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  // Close on backdrop click
  const handleDialogClick = useCallback((e: React.MouseEvent<HTMLDialogElement>) => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    // If the click target is the dialog itself (backdrop), close it
    const rect = dialog.getBoundingClientRect();
    const clickedInside =
      e.clientX >= rect.left &&
      e.clientX <= rect.right &&
      e.clientY >= rect.top &&
      e.clientY <= rect.bottom;
    if (!clickedInside) {
      onClose();
    }
  }, [onClose]);

  // Close on native cancel (Escape key)
  const handleCancel = useCallback((e: React.SyntheticEvent<HTMLDialogElement>) => {
    e.preventDefault();
    onClose();
  }, [onClose]);

  const handleRowClick = useCallback((policy: SamplePolicy) => {
    onSelect(policy);
  }, [onSelect]);

  // Group policies by category (preserving SAMPLE_CATEGORIES order)
  const grouped = SAMPLE_CATEGORIES.map((cat) => ({
    category: cat,
    icon: CATEGORY_ICONS[cat] ?? '',
    policies: SAMPLE_POLICIES.filter((p) => p.category === cat),
  }));

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      onClick={handleDialogClick}
      onCancel={handleCancel}
      className="fixed inset-0 m-auto w-[56rem] max-w-[90vw] max-h-[80vh] rounded-xl border border-slate-600/80 bg-slate-800 text-slate-100 shadow-2xl backdrop:bg-black/60 backdrop:backdrop-blur-sm p-0 overflow-hidden"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/80 bg-slate-800/95 sticky top-0 z-10">
        <h2 className="text-base font-bold text-slate-100 tracking-tight">
          Policy Examples
        </h2>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-100 transition-colors cursor-pointer p-1 rounded-lg hover:bg-slate-700/50"
          aria-label="Close"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Scrollable body */}
      <div className="overflow-y-auto px-6 py-4" style={{ maxHeight: 'calc(80vh - 4rem)' }}>
        {grouped.map(({ category, icon, policies }) => (
          <div key={category} className="mb-6 last:mb-2">
            {/* Category header */}
            <h3 className="text-sm font-semibold text-indigo-300 mb-2 flex items-center gap-2">
              <span>{icon}</span>
              <span>{category}</span>
            </h3>

            {/* Policy table */}
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-700/60">
                  <th className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold pb-1.5 pr-4 w-[38%]">
                    Policy name
                  </th>
                  <th className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold pb-1.5">
                    Description
                  </th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr
                    key={policy.id}
                    onClick={() => handleRowClick(policy)}
                    className="border-b border-slate-700/30 hover:bg-slate-700/40 cursor-pointer transition-colors group"
                  >
                    <td className="py-2 pr-4">
                      <code className="text-xs text-emerald-400 group-hover:text-emerald-300 font-mono">
                        {policy.name}
                      </code>
                    </td>
                    <td className="py-2 text-xs text-slate-400 group-hover:text-slate-300">
                      {policy.description}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </dialog>
  );
}
