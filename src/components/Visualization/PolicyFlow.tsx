import { useCallback, useEffect, useMemo, useRef } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import PolicyNodeComponent from './nodes/PolicyNode';
import RuleNodeComponent from './nodes/RuleNode';
import PolicyEdgeComponent from './edges/PolicyEdge';
import { policyToGraph } from '../../lib/transform/policyToGraph';
import { usePolicyContext } from '../../context/usePolicyContext';

const nodeTypes = {
  policyNode: PolicyNodeComponent,
  ruleNode: RuleNodeComponent,
};

const edgeTypes = {
  policyEdge: PolicyEdgeComponent,
};

export default function PolicyFlow() {
  const { state, dispatch } = usePolicyContext();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const { fitView } = useReactFlow();

  // Track the previous node count so we only fitView when the graph structure changes
  // (e.g., rules added/removed), not on every re-parse during live editing.
  const prevNodeCountRef = useRef(0);

  useEffect(() => {
    if (state.policy) {
      try {
        const graph = policyToGraph(state.policy, state.ruleLineRanges);
        setNodes(graph.nodes);
        setEdges(graph.edges);

        // Only fit view when node count changes (structural change) — avoids
        // jarring re-centering on every keystroke during live editing.
        if (graph.nodes.length !== prevNodeCountRef.current) {
          prevNodeCountRef.current = graph.nodes.length;
          setTimeout(() => fitView({ padding: 0.3, duration: 300 }), 50);
        }
      } catch (err) {
        console.error('policyToGraph failed:', err);
        dispatch({ type: 'SET_ERROR', payload: err instanceof Error ? err.message : 'Failed to build graph' });
      }
    } else {
      setNodes([]);
      setEdges([]);
      prevNodeCountRef.current = 0;
    }
  }, [state.policy, state.ruleLineRanges, setNodes, setEdges, fitView, dispatch]);

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    dispatch({ type: 'SELECT_NODE', payload: node.id });
  }, [dispatch]);

  const onPaneClick = useCallback(() => {
    dispatch({ type: 'SELECT_NODE', payload: null });
  }, [dispatch]);

  const defaultEdgeOptions = useMemo(() => ({
    type: 'policyEdge',
    animated: true,
  }), []);

  if (!state.policy) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500">
        <div className="text-center space-y-3">
          <div className="text-5xl opacity-30">
            <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <p className="text-sm">Import a Calico NetworkPolicy or GlobalNetworkPolicy YAML to visualize</p>
        </div>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      defaultEdgeOptions={defaultEdgeOptions}
      fitView
      fitViewOptions={{ padding: 0.3 }}
      minZoom={0.1}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
      className="bg-slate-900"
    >
      <Controls
        showInteractive={false}
        className="!bg-slate-800 !border-slate-700 !rounded-lg !shadow-lg"
      />

      <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
    </ReactFlow>
  );
}
