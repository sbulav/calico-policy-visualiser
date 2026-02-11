# Calico Network Policy Visualiser

A browser-based tool for Calico `NetworkPolicy` and `GlobalNetworkPolicy` visualization. Import YAML, see an interactive graph, highlighted source, and plain-English explanation. Everything runs client-side.

<img height="2150" alt="Calico Policy Visualiser screenshot" width="100%" src="https://github.com/user-attachments/assets/bce9bd3a-03f3-4ce3-98fd-d4fc0308508e" />

> **Try it now** — a live version is available at <https://sbulav.github.io/calico-visualiser/>

## Motivation

Cilium has the free [Network Policy Editor](https://editor.networkpolicy.io/) for Kubernetes network policies. Calico does not. Its visualization tools are in the paid Cloud and Enterprise versions.

This project is a free alternative. Load your Calico YAML. Get a graph of rules by traffic scope. See a text breakdown of what the policy allows or blocks.

## Features

- **Three panels**: YAML editor, graph visualization, explanation text. They sync on hover and selection.
- **YAML editor**: Editable CodeMirror editor with syntax highlighting. Edit the YAML directly and the graph and explanation update live (debounced at 400 ms). While the YAML is mid-edit and temporarily invalid, the last valid visualization stays on screen and an error banner shows the parse issue. Hover a rule in the graph to highlight the matching YAML lines and scroll to them.
- **Graph**: React Flow canvas. Central policy node connects to six rule categories (three for ingress, three for egress). Edges show action colors: green for Allow, red for Deny, amber for Log or mixed.
- **Rule groups**: Outside Cluster (CIDRs), In Namespace (pod selectors), In Cluster (cross-namespace). Each has rule cards with ports, selectors, services, and negation fields.
- **Inferred access**: Graph shows if Kubernetes DNS, any pod in namespace, or everything in cluster is allowed, denied, or uncertain. Defaults start as deny but catch-all rules override.
- **Explanation**: Bottom panel with policy details, flag descriptions (doNotTrack, preDNAT, applyOnForward), effective defaults, and per-rule text. Recognizes 20 well-known ports like Redis (6379), K8s API (6443), PostgreSQL (5432).
- **Supported fields**: Full Calico v3 spec. Selectors, namespaceSelector, serviceAccountSelector, tier, order, types (inferred if missing), rules with action (Allow/Deny/Log/Pass), protocol, icmp, source/destination (nets, ports, services, serviceAccounts), negation (notNets, notPorts, notSelector), http match, ipVersion, policy flags.
- **Samples**: Built-in NetworkPolicy (allow TCP 6379 from blue pods) and GlobalNetworkPolicy (k8s masters ingress).
- **Privacy**: No backend. No data sent anywhere.

## Quick start

### With Nix

```sh
nix develop
make init  # npm install
make dev   # http://localhost:5173
```

### Without Nix

Node.js 22 or later.

```sh
npm install
npm run dev  # http://localhost:5173
```

Load a sample or import YAML. Hover rules in the graph. Read the explanation.

## Usage

Click **Import YAML** in the toolbar and pick a `.yaml` or `.yml` file with a Calico NetworkPolicy or GlobalNetworkPolicy. Or use one of the sample buttons to load a built-in example. You can also type or paste YAML directly into the editor — the visualization updates as you type.

In the graph:
- Drag nodes to rearrange.
- Zoom with mouse wheel or on-screen controls.
- Hover rule cards to highlight the corresponding YAML lines.

Resize panels by dragging the divider handles. Collapse the explanation panel with its toggle.

Example: load the NetworkPolicy sample. One ingress rule appears in the "In Cluster" group. The edge is green (Allow). The explanation panel shows "[ALLOW] incoming TCP to port 6379 (Redis)".

## Development

### Commands

| Command | What it does |
|---------|--------------|
| `npm run dev` | Vite dev server with hot reload |
| `npm run build` | Type-check and production build to `dist/` |
| `npm run test` | Run Vitest tests |
| `npm run test:watch` | Tests in watch mode |
| `npm run lint` | ESLint check |
| `npm run preview` | Serve built app locally |
| `npx tsc --noEmit` | Type-check only |

`make` targets mirror these (e.g., `make test`, `make build`, `make lint`). Run `make help` for the full list.

### Project structure

```
src/
  main.tsx        Entry point
  App.tsx         Root (PolicyProvider + layout)
  index.css       Tailwind v4, CSS variables, overrides
  context/        React Context + useReducer state
  hooks/          Reusable React hooks (debounce, etc.)
  types/          Calico and graph type definitions
  lib/
    formatPort.ts Shared port formatting
    ipUtils.ts    IP/CIDR helpers
    parser/       YAML parsing and validation
    transform/    Policy to React Flow nodes and edges
    explain/      Policy to human-readable text
    matcher/      Selector parsing, rule matching, access testing
  components/
    Layout/       App shell, resizable panels
    Editor/       CodeMirror YAML editor (editable, with live parsing)
    Visualization/  React Flow canvas, custom nodes, edges
    Explanation/  Bottom explanation panel
    AccessTester/ Interactive access testing panel
  samples/        Built-in YAML examples
```

### Tech stack

- React 19, TypeScript 5.9, Vite 7
- React Flow (@xyflow/react) for the graph
- CodeMirror 6 (@uiw/react-codemirror) for YAML
- Tailwind CSS 4, dark theme with Slate palette
- js-yaml for parsing
- Vitest 4 for tests
- State: React Context + useReducer (no external state library)

Strict TypeScript with `verbatimModuleSyntax`, `noUnusedLocals`, `noUnusedParameters`, and `strictNullChecks`.

## Testing

252 tests across seven files.

| File | Tests | Covers |
|------|-------|--------|
| `yamlParser.test.ts` | 30 | Parsing, validation, all Calico fields |
| `yamlLineMapper.test.ts` | 9 | Line ranges for editor highlighting |
| `policyToGraph.test.ts` | 84 | Rule groups, edges, inferred statuses, defaults |
| `policyExplainer.test.ts` | 46 | Text sections, port names, rule descriptions |
| `selectorParser.test.ts` | 37 | Calico selector expression parsing and evaluation |
| `ruleMatcher.test.ts` | 28 | Rule matching against traffic specifications |
| `accessTester.test.ts` | 18 | End-to-end access verdict evaluation |

```sh
npm run test                                          # all tests
npx vitest run src/lib/parser/yamlParser.test.ts      # single file
```

## License

MIT. See [LICENSE](LICENSE). Author: Sergei Bulavintsev.
