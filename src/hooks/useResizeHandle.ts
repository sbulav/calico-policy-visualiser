import { useCallback, useState } from 'react';

type UseResizeHandleOptions = {
  /** Which mouse axis drives the resize. */
  axis: 'x' | 'y';
  /** Minimum panel size in px. */
  min: number;
  /** Maximum panel size in px; a function is re-evaluated on every move (e.g. viewport-relative). */
  max: number | (() => number);
  /** When true, dragging toward the start position grows the panel (right/bottom-anchored panels). */
  inverted?: boolean;
};

/**
 * Drag-to-resize behavior for panel dividers.
 *
 * On mouse down, captures the start position/size and tracks document-level
 * mousemove/mouseup until release, clamping the size to [min, max].
 */
export function useResizeHandle(
  initialSize: number,
  { axis, min, max, inverted = false }: UseResizeHandleOptions,
) {
  const [size, setSize] = useState(initialSize);
  const [isResizing, setIsResizing] = useState(false);

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);

    const startPos = axis === 'x' ? e.clientX : e.clientY;
    const startSize = size;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const pos = axis === 'x' ? moveEvent.clientX : moveEvent.clientY;
      const diff = inverted ? startPos - pos : pos - startPos;
      const maxSize = typeof max === 'function' ? max() : max;
      setSize(Math.max(min, Math.min(maxSize, startSize + diff)));
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [axis, min, max, inverted, size]);

  return { size, isResizing, handleResizeStart };
}
