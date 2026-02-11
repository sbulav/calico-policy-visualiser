import { useContext } from 'react';
import { PolicyContext } from './policyContextDef';

export function usePolicyContext() {
  const context = useContext(PolicyContext);
  if (!context) {
    throw new Error('usePolicyContext must be used within a PolicyProvider');
  }
  return context;
}
