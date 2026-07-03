import { useCallback, useEffect, useMemo, useRef } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { yaml } from '@codemirror/lang-yaml';
import { createTheme } from '@uiw/codemirror-themes';
import { tags as t } from '@lezer/highlight';
import { StateEffect, StateField, type Range } from '@codemirror/state';
import { Decoration, type DecorationSet, EditorView } from '@codemirror/view';
import { usePolicyState } from '../../context/usePolicyContext';

const darkTheme = createTheme({
  theme: 'dark',
  settings: {
    background: '#0f172a',
    foreground: '#e2e8f0',
    caret: '#6366f1',
    selection: '#6366f140',
    selectionMatch: '#6366f120',
    gutterBackground: '#1e293b',
    gutterForeground: '#475569',
    gutterActiveForeground: '#94a3b8',
    gutterBorder: '#334155',
    lineHighlight: '#1e293b50',
  },
  styles: [
    { tag: t.keyword, color: '#c084fc' },
    { tag: t.string, color: '#86efac' },
    { tag: t.number, color: '#fbbf24' },
    { tag: t.bool, color: '#f472b6' },
    { tag: t.null, color: '#94a3b8' },
    { tag: t.propertyName, color: '#67e8f9' },
    { tag: t.comment, color: '#475569' },
    { tag: t.operator, color: '#94a3b8' },
    { tag: t.punctuation, color: '#64748b' },
    { tag: t.meta, color: '#818cf8' },
    { tag: t.atom, color: '#f472b6' },
  ],
});

// --- CodeMirror line-highlight extension ---

// Effect to set the highlighted line range (null to clear)
const setHighlightEffect = StateEffect.define<{ from: number; to: number } | null>();

// Line decoration applied to highlighted lines
const highlightLineDeco = Decoration.line({ class: 'cm-highlighted-rule' });

// StateField that maintains the current set of line decorations
const highlightField = StateField.define<DecorationSet>({
  create() {
    return Decoration.none;
  },
  update(decos, tr) {
    for (const effect of tr.effects) {
      if (effect.is(setHighlightEffect)) {
        if (!effect.value) {
          return Decoration.none;
        }
        const { from, to } = effect.value;
        const doc = tr.state.doc;
        const maxLine = doc.lines;
        const startLine = Math.max(1, Math.min(from, maxLine));
        const endLine = Math.max(1, Math.min(to, maxLine));
        const decorations: Range<Decoration>[] = [];
        for (let line = startLine; line <= endLine; line++) {
          const lineStart = doc.line(line).from;
          decorations.push(highlightLineDeco.range(lineStart));
        }
        return Decoration.set(decorations, true);
      }
    }
    return decos;
  },
  provide: (f) => EditorView.decorations.from(f),
});

type YamlViewerProps = {
  onYamlChange: (value: string) => void;
};

export default function YamlViewer({ onYamlChange }: YamlViewerProps) {
  const state = usePolicyState();
  const editorViewRef = useRef<EditorView | null>(null);

  // Capture the EditorView when CodeMirror creates it
  const handleCreateEditor = useCallback((view: EditorView) => {
    editorViewRef.current = view;
  }, []);

  // Forward editor changes to the parent via the onYamlChange callback
  const handleChange = useCallback((value: string) => {
    onYamlChange(value);
  }, [onYamlChange]);

  // React to highlightedLines changes — dispatch CodeMirror effects
  useEffect(() => {
    const view = editorViewRef.current;
    if (!view) return;

    const range = state.highlightedLines;

    if (range) {
      view.dispatch({
        effects: setHighlightEffect.of({ from: range.startLine, to: range.endLine }),
      });

      // Scroll the highlighted range into view (center it)
      const doc = view.state.doc;
      const maxLine = doc.lines;
      const targetLine = Math.max(1, Math.min(range.startLine, maxLine));
      const linePos = doc.line(targetLine).from;
      view.dispatch({
        effects: EditorView.scrollIntoView(linePos, { y: 'center' }),
      });
    } else {
      view.dispatch({
        effects: setHighlightEffect.of(null),
      });
    }
  }, [state.highlightedLines]);

  // Combine extensions: YAML language + highlight field
  const extensions = useMemo(() => [yaml(), highlightField], []);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-700 bg-slate-800/50">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
          <span className="text-xs font-semibold text-slate-300">YAML</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-400 font-mono">editable</span>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-auto">
        {state.yamlContent ? (
          <CodeMirror
            value={state.yamlContent}
            height="100%"
            extensions={extensions}
            theme={darkTheme}
            onChange={handleChange}
            onCreateEditor={handleCreateEditor}
            basicSetup={{
              lineNumbers: true,
              highlightActiveLineGutter: true,
              highlightActiveLine: true,
              foldGutter: true,
            }}
          />
        ) : (
          <div className="flex items-center justify-center h-full text-slate-500">
            <p className="text-xs">No policy loaded</p>
          </div>
        )}
      </div>

      {state.parseWarnings.length > 0 && (
        <div className="px-3 py-2 bg-amber-500/10 border-t border-amber-500/30">
          <div className="flex items-start gap-2">
            <svg className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86l-8.6 14.86A1 1 0 002.56 20h18.88a1 1 0 00.87-1.28l-8.6-14.86a1 1 0 00-1.72 0z" />
            </svg>
            <div className="space-y-0.5">
              {state.parseWarnings.map((warning, i) => (
                <div key={i} className="text-xs text-amber-300">{warning}</div>
              ))}
            </div>
          </div>
        </div>
      )}

      {state.parseError && (
        <div className="px-3 py-2 bg-red-500/10 border-t border-red-500/30">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="text-xs text-red-300">{state.parseError}</span>
          </div>
        </div>
      )}
    </div>
  );
}
