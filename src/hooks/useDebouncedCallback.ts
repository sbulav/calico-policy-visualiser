import { useCallback, useEffect, useMemo, useRef } from 'react';

interface DebouncedHandle<Args extends unknown[]> {
  /** Schedule the callback after `delay` ms of inactivity. */
  call: (...args: Args) => void;
  /** Cancel any pending invocation. */
  cancel: () => void;
  /** Cancel the pending timer and invoke the callback immediately. */
  flush: (...args: Args) => void;
}

/**
 * Returns a debounced handle for the given callback.
 * The callback is invoked after `delay` ms of inactivity.
 */
export function useDebouncedCallback<Args extends unknown[]>(
  callback: (...args: Args) => void,
  delay: number,
): DebouncedHandle<Args> {
  const callbackRef = useRef(callback);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Always keep the latest callback without resetting the timer
  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  const call = useCallback((...args: Args) => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
    }
    timerRef.current = setTimeout(() => {
      timerRef.current = null;
      callbackRef.current(...args);
    }, delay);
  }, [delay]);

  const cancel = useCallback(() => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const flush = useCallback((...args: Args) => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    callbackRef.current(...args);
  }, []);

  return useMemo(() => ({ call, cancel, flush }), [call, cancel, flush]);
}
