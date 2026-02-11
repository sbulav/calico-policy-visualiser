import { useReducer, type ReactNode } from 'react';
import { PolicyContext, policyReducer, initialState } from './policyContextDef';

export function PolicyProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(policyReducer, initialState);

  return (
    <PolicyContext.Provider value={{ state, dispatch }}>
      {children}
    </PolicyContext.Provider>
  );
}
