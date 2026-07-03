import { useReducer, type ReactNode } from 'react';
import { PolicyStateContext, PolicyDispatchContext, policyReducer, initialState } from './policyContextDef';

export function PolicyProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(policyReducer, initialState);

  return (
    <PolicyStateContext.Provider value={state}>
      <PolicyDispatchContext.Provider value={dispatch}>
        {children}
      </PolicyDispatchContext.Provider>
    </PolicyStateContext.Provider>
  );
}
