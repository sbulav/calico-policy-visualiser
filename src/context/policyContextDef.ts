import { createContext } from 'react';
import type { ResolvedPolicy } from '../types/calico';
import type { SourceRange } from '../types/graph';
import type { RuleLineRanges } from '../lib/parser/yamlLineMapper';

interface PolicyState {
  yamlContent: string;
  policy: ResolvedPolicy | null;
  parseError: string | null;
  parseWarnings: string[];
  selectedNodeId: string | null;
  ruleLineRanges: RuleLineRanges | null;
  highlightedLines: SourceRange | null;
}

type PolicyAction =
  | { type: 'SET_YAML'; payload: string }
  | { type: 'SET_POLICY'; payload: { policy: ResolvedPolicy | null; ruleLineRanges: RuleLineRanges | null; warnings: string[] } }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SELECT_NODE'; payload: string | null }
  | { type: 'HIGHLIGHT_LINES'; payload: SourceRange | null };

export const initialState: PolicyState = {
  yamlContent: '',
  policy: null,
  parseError: null,
  parseWarnings: [],
  selectedNodeId: null,
  ruleLineRanges: null,
  highlightedLines: null,
};

export function policyReducer(state: PolicyState, action: PolicyAction): PolicyState {
  switch (action.type) {
    case 'SET_YAML':
      return { ...state, yamlContent: action.payload };
    case 'SET_POLICY':
      return { ...state, policy: action.payload.policy, ruleLineRanges: action.payload.ruleLineRanges, parseError: null, parseWarnings: action.payload.warnings };
    case 'SET_ERROR':
      // Preserve the last valid policy/ruleLineRanges so the visualization
      // stays visible while the user is mid-edit with temporarily invalid YAML.
      return { ...state, parseError: action.payload, parseWarnings: [] };
    case 'SELECT_NODE':
      return { ...state, selectedNodeId: action.payload };
    case 'HIGHLIGHT_LINES':
      return { ...state, highlightedLines: action.payload };
    default:
      return state;
  }
}

export const PolicyContext = createContext<{
  state: PolicyState;
  dispatch: React.Dispatch<PolicyAction>;
} | null>(null);
