import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { encodePolicyParam } from '../../lib/urlPolicy';

type UrlPolicyModalProps = {
  open: boolean;
  onClose: () => void;
  yamlContent: string;
  onLoadUrl: (url: string) => void;
};

export default function UrlPolicyModal({ open, onClose, yamlContent, onLoadUrl }: UrlPolicyModalProps) {
  const [urlInput, setUrlInput] = useState('');
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'error'>('idle');
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Reset transient copy feedback when the modal is dismissed so it
  // reopens in a clean state (the component stays mounted while closed).
  const handleClose = useCallback(() => {
    setCopyStatus('idle');
    onClose();
  }, [onClose]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (open && !dialog.open) {
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  const handleDialogClick = useCallback((e: React.MouseEvent<HTMLDialogElement>) => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    const rect = dialog.getBoundingClientRect();
    const clickedInside =
      e.clientX >= rect.left &&
      e.clientX <= rect.right &&
      e.clientY >= rect.top &&
      e.clientY <= rect.bottom;
    if (!clickedInside) {
      handleClose();
    }
  }, [handleClose]);

  const handleCancel = useCallback((e: React.SyntheticEvent<HTMLDialogElement>) => {
    e.preventDefault();
    handleClose();
  }, [handleClose]);

  const shareLink = useMemo(() => {
    if (typeof window === 'undefined') {
      return '';
    }

    if (!yamlContent) {
      return '';
    }

    const base = `${window.location.origin}${window.location.pathname}`;
    const encoded = encodePolicyParam(yamlContent, true);
    return `${base}#policy=${encoded}`;
  }, [yamlContent]);

  const handleCopy = useCallback(async () => {
    if (!shareLink) {
      return;
    }

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(shareLink);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = shareLink;
        textarea.setAttribute('readonly', 'true');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopyStatus('copied');
    } catch {
      setCopyStatus('error');
    }
  }, [shareLink]);

  const handleLoadUrl = useCallback(() => {
    const trimmed = urlInput.trim();
    if (!trimmed) {
      return;
    }
    onLoadUrl(trimmed);
  }, [onLoadUrl, urlInput]);

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      onClick={handleDialogClick}
      onCancel={handleCancel}
      className="fixed inset-0 m-auto w-[36rem] max-w-[92vw] rounded-xl border border-slate-600/80 bg-slate-800 text-slate-100 shadow-2xl backdrop:bg-black/60 backdrop:backdrop-blur-sm p-0 overflow-hidden"
    >
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-700/80 bg-slate-800/95">
        <div>
          <h2 className="text-sm font-bold text-slate-100 tracking-tight">Load or Share Policy</h2>
          <p className="text-[11px] text-slate-400">Fetch YAML from a URL or copy a deep link.</p>
        </div>
        <button
          onClick={handleClose}
          className="text-slate-400 hover:text-slate-100 transition-colors cursor-pointer p-1 rounded-lg hover:bg-slate-700/50"
          aria-label="Close"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="px-5 py-4 space-y-5">
        <div className="space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Load from URL</div>
          <div className="flex items-center gap-2">
            <input
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
              placeholder="https://example.com/policy.yaml"
              className="flex-1 px-3 py-2 text-xs rounded-lg bg-slate-900/60 border border-slate-700 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
            />
            <button
              onClick={handleLoadUrl}
              className="text-xs px-3 py-2 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 transition-colors"
            >
              Fetch YAML
            </button>
          </div>
          <p className="text-[11px] text-slate-500">Requires CORS access on the remote host.</p>
        </div>

        <div className="space-y-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Share link</div>
          <div className="flex items-center gap-2">
            <input
              readOnly
              value={shareLink}
              placeholder="Load a policy to generate a link"
              className="flex-1 px-3 py-2 text-xs rounded-lg bg-slate-900/60 border border-slate-700 text-slate-200 placeholder:text-slate-500"
            />
            <button
              onClick={handleCopy}
              disabled={!shareLink}
              className={`text-xs px-3 py-2 rounded-lg border transition-colors ${
                shareLink
                  ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30 hover:bg-indigo-500/30'
                  : 'bg-slate-800/60 text-slate-500 border-slate-700 cursor-not-allowed'
              }`}
            >
              {copyStatus === 'copied' ? 'Copied' : 'Copy'}
            </button>
          </div>
          {copyStatus === 'error' && (
            <div className="text-[11px] text-red-400">Copy failed. Select the link and copy manually.</div>
          )}
        </div>
      </div>
    </dialog>
  );
}
