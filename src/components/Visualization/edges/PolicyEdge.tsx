import { memo } from 'react';
import { BaseEdge, getBezierPath, EdgeLabelRenderer, type EdgeProps } from '@xyflow/react';
import type { PolicyEdgeData } from '../../../types/graph';

type PolicyEdgeComponentProps = EdgeProps & { data?: PolicyEdgeData };

function PolicyEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  data,
  markerEnd,
}: PolicyEdgeComponentProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const strokeColor = style?.stroke as string || '#64748b';

  // Build label text from rules (skip for outsideCluster — shown per-CIDR card instead)
  let labelText = '';
  if (data?.category !== 'outsideCluster' && data?.rules && data.rules.length > 0) {
    const summary = data.rules.map(r => {
      const parts: string[] = [];
      if (r.protocol) parts.push(r.protocol);
      // Use entity ports first, fall back to opposite-side ports
      const effectivePorts = (r.ports && r.ports.length > 0)
        ? r.ports
        : (r.dstPorts && r.dstPorts.length > 0)
          ? r.dstPorts
          : (r.srcPorts && r.srcPorts.length > 0)
            ? r.srcPorts
            : [];
      if (effectivePorts.length > 0) parts.push(`:${effectivePorts.join(',')}`);
      return parts.join('') || r.action;
    });
    const unique = [...new Set(summary)];
    labelText = unique.join(' | ');
  }

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          ...style,
          strokeWidth: 2,
          stroke: strokeColor,
        }}
      />
      {labelText && (
        <EdgeLabelRenderer>
          <div
            className="px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold border backdrop-blur-sm whitespace-nowrap"
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: 'all',
              backgroundColor: `${strokeColor}15`,
              borderColor: `${strokeColor}40`,
              color: strokeColor,
            }}
          >
            {labelText}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export default memo(PolicyEdgeComponent);
