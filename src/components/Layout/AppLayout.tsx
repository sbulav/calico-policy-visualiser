import { useCallback, useEffect, useRef, useState } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import YamlViewer from '../Editor/YamlViewer';
import PolicyFlow from '../Visualization/PolicyFlow';
import PolicyExplanation from '../Explanation/PolicyExplanation';
import ExamplesModal from './ExamplesModal';
import UrlPolicyModal from './UrlPolicyModal';
import AccessTesterPanel from '../AccessTester/AccessTesterPanel';
import { usePolicyState, usePolicyDispatch } from '../../context/usePolicyContext';
import { parseYaml } from '../../lib/parser/yamlParser';
import { decodePolicyParam, MAX_POLICY_YAML_CHARS } from '../../lib/urlPolicy';
import { useDebouncedCallback } from '../../hooks/useDebouncedCallback';
import type { SamplePolicy } from '../../samples';
import { SAMPLE_POLICIES } from '../../samples';

function parseParams(raw: string, plusAsSpace: boolean) {
  const params: Record<string, string> = {};
  if (!raw) {
    return params;
  }

  const trimmed = raw.replace(/^[?#]/, '');
  if (!trimmed) {
    return params;
  }

  for (const part of trimmed.split('&')) {
    if (!part) continue;
    const [rawKey, ...rest] = part.split('=');
    if (!rawKey) continue;
    const rawValue = rest.join('=');
    const keyInput = plusAsSpace ? rawKey.replace(/\+/g, ' ') : rawKey;
    const valueInput = plusAsSpace ? rawValue.replace(/\+/g, ' ') : rawValue;
    try {
      const key = decodeURIComponent(keyInput);
      const value = decodeURIComponent(valueInput);
      params[key] = value;
    } catch {
      continue;
    }
  }

  return params;
}

function getPolicyParams() {
  if (typeof window === 'undefined') {
    return { url: null, policy: null };
  }

  const searchParams = parseParams(window.location.search, true);
  const hashParams = parseParams(window.location.hash, false);

  return {
    url: searchParams.url ?? hashParams.url ?? null,
    policy: searchParams.policy ?? hashParams.policy ?? null,
  };
}

export default function AppLayout() {
  const state = usePolicyState();
  const dispatch = usePolicyDispatch();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const urlLoadControllerRef = useRef<AbortController | null>(null);
  const [explanationCollapsed, setExplanationCollapsed] = useState(false);
  const [explanationHeight, setExplanationHeight] = useState(208);
  const [leftPanelWidth, setLeftPanelWidth] = useState(350);
  const [isResizing, setIsResizing] = useState(false);
  const [isResizingExplanation, setIsResizingExplanation] = useState(false);
  const [examplesOpen, setExamplesOpen] = useState(false);
  const [urlModalOpen, setUrlModalOpen] = useState(false);
  const [testerOpen, setTesterOpen] = useState(false);
  const [rightPanelWidth, setRightPanelWidth] = useState(320);
  const [isResizingRight, setIsResizingRight] = useState(false);

  // Parse YAML and dispatch the result (policy or error) to state.
  const parseAndDispatch = useCallback((yamlContent: string) => {
    const result = parseYaml(yamlContent);
    if (result.error) {
      dispatch({ type: 'SET_ERROR', payload: result.error });
    } else {
      dispatch({ type: 'SET_POLICY', payload: { policy: result.policy, ruleLineRanges: result.ruleLineRanges, warnings: result.warnings } });
    }
  }, [dispatch]);

  // Debounced version — used when the user edits YAML in the editor.
  // 400ms strikes a balance between responsiveness and avoiding jitter.
  const debouncedParse = useDebouncedCallback(parseAndDispatch, 400);

  // Called by file import and example selection — parses immediately (no debounce).
  const loadYaml = useCallback((yamlContent: string) => {
    debouncedParse.cancel();
    dispatch({ type: 'SET_YAML', payload: yamlContent });
    parseAndDispatch(yamlContent);
  }, [dispatch, parseAndDispatch, debouncedParse]);

  const fetchAndLoadUrl = useCallback(async (url: string) => {
    urlLoadControllerRef.current?.abort();
    const controller = new AbortController();
    urlLoadControllerRef.current = controller;
    const timeoutId = window.setTimeout(() => controller.abort(), 15_000);

    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          Accept: 'text/yaml, text/plain, */*',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch policy (${response.status} ${response.statusText})`);
      }

      const contentLength = Number(response.headers.get('content-length'));
      if (Number.isFinite(contentLength) && contentLength > MAX_POLICY_YAML_CHARS) {
        throw new Error('Fetched policy is too large.');
      }

      const yamlContent = await response.text();
      if (yamlContent.length > MAX_POLICY_YAML_CHARS) {
        throw new Error('Fetched policy is too large.');
      }

      loadYaml(yamlContent);
    } catch (error) {
      if (controller.signal.aborted) return;
      const message = error instanceof Error ? error.message : 'Failed to load policy from URL.';
      dispatch({ type: 'SET_ERROR', payload: message });
    } finally {
      window.clearTimeout(timeoutId);
    }
  }, [dispatch, loadYaml]);

  const loadFromLocation = useCallback(() => {
    const { url, policy } = getPolicyParams();
    if (!url && !policy) {
      return;
    }

    const load = async () => {
      if (url) {
        await fetchAndLoadUrl(url);
        return;
      }

      if (policy) {
        const result = decodePolicyParam(policy);
        if (result.error) {
          dispatch({ type: 'SET_ERROR', payload: result.error });
          return;
        }

        if (result.yaml) {
          loadYaml(result.yaml);
        }
      }
    };

    void load();
  }, [dispatch, fetchAndLoadUrl, loadYaml]);

  useEffect(() => {
    loadFromLocation();

    const handleLocationChange = () => {
      loadFromLocation();
    };

    window.addEventListener('hashchange', handleLocationChange);
    window.addEventListener('popstate', handleLocationChange);

    return () => {
      window.removeEventListener('hashchange', handleLocationChange);
      window.removeEventListener('popstate', handleLocationChange);
      urlLoadControllerRef.current?.abort();
    };
  }, [loadFromLocation]);

  // Auto-load default deny-all policy on first mount if editor is empty.
  useEffect(() => {
    const { url, policy } = getPolicyParams();
    if (!state.yamlContent && !url && !policy) {
      const defaultDeny = SAMPLE_POLICIES.find(p => p.id === 'default-deny-all');
      if (defaultDeny) {
        loadYaml(defaultDeny.yaml);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Called by the editor on every keystroke.
  // Updates yamlContent immediately for a responsive editor, debounces the parse.
  const handleYamlChange = useCallback((yamlContent: string) => {
    dispatch({ type: 'SET_YAML', payload: yamlContent });
    debouncedParse.call(yamlContent);
  }, [dispatch, debouncedParse]);

  const handleExampleSelect = useCallback((policy: SamplePolicy) => {
    loadYaml(policy.yaml);
    setExamplesOpen(false);
  }, [loadYaml]);

  const handleFileImport = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleUrlLoad = useCallback((url: string) => {
    setUrlModalOpen(false);
    void fetchAndLoadUrl(url);
  }, [fetchAndLoadUrl]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_POLICY_YAML_CHARS) {
      dispatch({ type: 'SET_ERROR', payload: 'Imported file is too large.' });
      e.target.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result;
      if (typeof content === 'string' && content) {
        loadYaml(content);
      }
    };
    reader.onerror = () => {
      dispatch({ type: 'SET_ERROR', payload: 'Failed to read the imported file.' });
    };
    reader.readAsText(file);
    // Reset input so same file can be loaded again
    e.target.value = '';
  }, [dispatch, loadYaml]);

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);

    const startX = e.clientX;
    const startWidth = leftPanelWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const diff = moveEvent.clientX - startX;
      const newWidth = Math.max(250, Math.min(600, startWidth + diff));
      setLeftPanelWidth(newWidth);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [leftPanelWidth]);

  const handleExplanationResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizingExplanation(true);

    const startY = e.clientY;
    const startHeight = explanationHeight;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const diff = startY - moveEvent.clientY;
      const maxHeight = Math.round(window.innerHeight * 2 / 3);
      const newHeight = Math.max(80, Math.min(maxHeight, startHeight + diff));
      setExplanationHeight(newHeight);
    };

    const handleMouseUp = () => {
      setIsResizingExplanation(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [explanationHeight]);

  const handleRightResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizingRight(true);

    const startX = e.clientX;
    const startWidth = rightPanelWidth;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const diff = startX - moveEvent.clientX;
      const newWidth = Math.max(260, Math.min(500, startWidth + diff));
      setRightPanelWidth(newWidth);
    };

    const handleMouseUp = () => {
      setIsResizingRight(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [rightPanelWidth]);

  return (
    <div className="h-screen flex flex-col bg-slate-900">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-slate-700 bg-slate-800/80 backdrop-blur-sm shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <svg className="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
            </svg>
            <h1 className="text-sm font-bold text-slate-100">Calico Network Policy Visualiser <span className="text-xs font-normal text-slate-300">v{__APP_VERSION__}</span></h1>
          </div>

          {/* Examples button */}
          <button
            onClick={() => setExamplesOpen(true)}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-indigo-500/20 text-indigo-300 hover:bg-indigo-500/30 border border-indigo-500/30 transition-colors cursor-pointer ml-4"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            Examples
          </button>

          {/* Test Access button */}
          <button
            onClick={() => setTesterOpen(!testerOpen)}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors cursor-pointer ${
              testerOpen
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30 hover:bg-indigo-500/30'
            }`}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Test Access
          </button>
        </div>

        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".yaml,.yml"
            onChange={handleFileChange}
            className="hidden"
          />
          <button
            onClick={() => setUrlModalOpen(true)}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-indigo-500/20 text-indigo-300 hover:bg-indigo-500/30 border border-indigo-500/30 transition-colors cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 010 5.656m-1.414-1.414a2 2 0 010-2.828m3.536-3.536a6 6 0 010 8.485m-7.071-7.071a6 6 0 000 8.485M10.172 13.828a4 4 0 010-5.656" />
            </svg>
            URL / Share
          </button>
          <button
            onClick={handleFileImport}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-indigo-500/20 text-indigo-300 hover:bg-indigo-500/30 border border-indigo-500/30 transition-colors cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            Import YAML
          </button>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 flex min-h-0">
        {/* Left panel - YAML Viewer */}
        <div
          className="border-r border-slate-700 shrink-0 overflow-hidden"
          style={{ width: leftPanelWidth }}
        >
          <YamlViewer onYamlChange={handleYamlChange} />
        </div>

        {/* Resize handle */}
        <div
          className={`w-1 cursor-col-resize hover:bg-indigo-500/50 transition-colors shrink-0 ${
            isResizing ? 'bg-indigo-500/50' : 'bg-transparent'
          }`}
          onMouseDown={handleResizeStart}
        />

        {/* Center panel - Visualization */}
        <div className="flex-1 min-w-0">
          <ReactFlowProvider>
            <PolicyFlow />
          </ReactFlowProvider>
        </div>

        {/* Right panel - Access Tester */}
        {testerOpen && (
          <>
            {/* Resize handle */}
            <div
              className={`w-1 cursor-col-resize hover:bg-indigo-500/50 transition-colors shrink-0 ${
                isResizingRight ? 'bg-indigo-500/50' : 'bg-transparent'
              }`}
              onMouseDown={handleRightResizeStart}
            />
            <div
              className="border-l border-slate-700 shrink-0 overflow-hidden"
              style={{ width: rightPanelWidth }}
            >
              <AccessTesterPanel onClose={() => setTesterOpen(false)} />
            </div>
          </>
        )}
      </div>

      {/* Bottom panel - Explanation */}
      {state.policy && (
        <div
          className="border-t border-slate-700 shrink-0"
          style={{ height: explanationCollapsed ? 32 : explanationHeight }}
        >
          {/* Resize handle */}
          {!explanationCollapsed && (
            <div
              className={`h-1 cursor-row-resize hover:bg-indigo-500/50 transition-colors ${
                isResizingExplanation ? 'bg-indigo-500/50' : 'bg-transparent'
              }`}
              onMouseDown={handleExplanationResizeStart}
            />
          )}
          <div className="flex items-center justify-between px-3 h-8 border-b border-slate-700/50 bg-slate-800/50">
            <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Explanation</span>
            <button
              onClick={() => setExplanationCollapsed(!explanationCollapsed)}
              className="text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
            >
              <svg
                className={`w-4 h-4 transition-transform ${explanationCollapsed ? 'rotate-180' : ''}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
          </div>
          {!explanationCollapsed && (
            <div style={{ height: 'calc(100% - 2rem - 4px)' }} className="overflow-hidden">
              <PolicyExplanation />
            </div>
          )}
        </div>
      )}

      {/* Examples modal */}
      <ExamplesModal
        open={examplesOpen}
        onClose={() => setExamplesOpen(false)}
        onSelect={handleExampleSelect}
      />
      <UrlPolicyModal
        open={urlModalOpen}
        onClose={() => setUrlModalOpen(false)}
        yamlContent={state.yamlContent}
        onLoadUrl={handleUrlLoad}
      />
    </div>
  );
}
