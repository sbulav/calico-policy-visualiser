import { useContext } from 'react';
import { PolicyStateContext, PolicyDispatchContext } from './policyContextDef';

export function usePolicyState() {
  const state = useContext(PolicyStateContext);
  if (!state) {
    throw new Error('usePolicyState must be used within a PolicyProvider');
  }
  return state;
}

export function usePolicyDispatch() {
  const dispatch = useContext(PolicyDispatchContext);
  if (!dispatch) {
    throw new Error('usePolicyDispatch must be used within a PolicyProvider');
  }
  return dispatch;
}
