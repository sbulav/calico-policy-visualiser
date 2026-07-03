# AGENTS.md — Calico Network Policy Visualizer

Guidelines for AI coding agents working in this repository.

## Project Overview

Client-side React SPA that visualizes Calico `NetworkPolicy` and `GlobalNetworkPolicy`
resources. Users import YAML files or edit YAML directly in the browser; the app parses
them and renders an interactive node/edge diagram (React Flow) with human-readable
explanations. No backend, no API calls, no routing — everything runs in the browser.

## Repository Structure

```
/                           Repo root (configs, Makefile, index.html)
/src/
  main.tsx                  Entry point
  App.tsx                   Root component (wraps PolicyProvider)
  index.css                 Global styles, Tailwind import, CSS variables
  context/                  React Context + useReducer state management
  hooks/                    Reusable React hooks (debounce, etc.)
  types/                    TypeScript type definitions (calico.ts, graph.ts)
  lib/parser/               YAML parsing and validation (no React)
  lib/transform/            Policy → React Flow nodes/edges (no React)
  lib/explain/              Policy → human-readable text (no React)
  lib/matcher/              Selector parsing, rule matching, access testing (no React)
  lib/urlPolicy.ts          Deep-link policy encode/decode (lz-string)
  components/Layout/        App shell, panel layout, examples/URL modals
  components/Editor/        Editable CodeMirror YAML editor with live parsing
  components/Visualization/ React Flow canvas, custom nodes, custom edges
  components/Explanation/   Bottom explanation panel
  components/AccessTester/  Interactive access testing side panel
  samples/                  Embedded sample YAML strings + raw files
```

## Build / Lint / Dev Commands

All commands run from the repo root:

| Command           | What it does                                    |
|-------------------|-------------------------------------------------|
| `npm run dev`     | Start Vite dev server (hot reload)              |
| `npm run build`   | TypeScript check (`tsc -b`) then Vite build     |
| `npm run lint`    | ESLint (flat config, v9)                        |
| `npm run preview` | Serve production build locally                  |
| `npm run test`    | Run Vitest test suite (single run)              |
| `npm run test:watch` | Run Vitest in watch mode                     |
| `npx tsc --noEmit`| Type-check only (no build output)               |

A `Makefile` is provided for convenience: `make dev`, `make test`, `make build`, etc.
Run a single test with: `npx vitest run src/path/to/file.test.ts`

## Tech Stack

- **React 19** + **TypeScript ~5.9** + **Vite 7** (ESM-first, `"type": "module"`)
- **React Flow** (`@xyflow/react`) — node/edge diagram with drag, zoom, pan
- **CodeMirror 6** (`@uiw/react-codemirror`) — editable YAML editor with live parsing
- **Tailwind CSS v4** — via `@tailwindcss/vite` plugin (no PostCSS, no tailwind.config)
- **js-yaml** — YAML parsing
- State: React Context + `useReducer` (no Redux/Zustand)

## TypeScript Conventions

**Strict mode is ON.** The following are compiler errors, not suggestions:

- `verbatimModuleSyntax: true` — **always** use `import type { ... }` for type-only
  imports. For mixed imports, use inline `type`: `import { foo, type Bar } from '...'`
- `noUnusedLocals: true` / `noUnusedParameters: true` — no dead code
- `erasableSyntaxOnly: true` — no `enum`, no `namespace`, no parameter properties
- `noFallthroughCasesInSwitch: true`
- `strict: true` — includes strictNullChecks, noImplicitAny, etc.

**Type definitions:**
- Use `type` aliases for union types and component props
- Use `interface` for object shapes (policy specs, parse results)
- Props types use intersection: `type FooProps = NodeProps & { data: FooData }`
- Avoid `any` — use `unknown` and narrow with type guards
- Non-null assertion (`!`) only when guaranteed (e.g., `Map.get()` after `Map.has()`)

## Code Style

**Formatting (no Prettier configured — maintain manually):**
- 2-space indentation, no tabs
- Always semicolons
- Single quotes in TS/JS, double quotes in JSX attributes
- Trailing commas in multiline constructs
- No enforced line length, but keep logic readable

**Imports — order by group, blank line between groups:**
1. React / framework (`react`, `react-dom`)
2. Third-party libraries (`@xyflow/react`, `js-yaml`, etc.)
3. Internal modules (relative paths: `../../lib/...`, `../../context/...`)
4. CSS / side-effect imports (`./index.css`, `@xyflow/react/dist/style.css`)

No path aliases — use relative paths only.

**Naming:**
- Files: PascalCase for components (`PolicyNode.tsx`), camelCase for logic (`yamlParser.ts`)
- Components: PascalCase function names; React Flow node/edge components get `Component` suffix
- Functions: camelCase; `handle*` prefix for event handlers, `on*` for callbacks from libs
- Types/interfaces: PascalCase; props suffixed with `Props`
- Constants: `UPPER_SNAKE_CASE` for module-level constants
- Variables: camelCase

## React Patterns

**Component structure:**
- Use `function` declarations (not arrow functions) for components
- One main exported component per file
- Small helper components can live in the same file (not exported)
- Default exports for components; named exports for hooks and utilities

**Memoization:**
- `React.memo()` on React Flow custom node/edge components (they re-render often)
- `useCallback` for event handlers and functions passed as props
- `useMemo` for stable reference objects
- Do NOT memo layout or page-level components

**State management:**
- Global state via split contexts (`PolicyStateContext` / `PolicyDispatchContext`, useReducer
  with discriminated union actions). Use `usePolicyState()` / `usePolicyDispatch()`; prefer
  dispatch-only in memoized React Flow nodes so state changes don't re-render them
- Local UI state (panel width, collapsed) via `useState`
- `useRef` for DOM element references

**Error handling:**
- Parser returns `{ policy: T | null, error: string | null }` — never throws
- Context hooks throw if used outside provider (programmer error)
- Display parse errors in UI (red banner below YAML editor)
- No error boundaries currently — add one if implementing async operations

## Styling

- **Tailwind CSS v4** utility classes — no CSS modules, no CSS-in-JS
- Dark theme only (Slate palette). CSS variables defined in `index.css` `:root`
- Domain colors: `--color-allow` (green), `--color-deny` (red), `--color-log` (amber), `--color-pass` (blue)
- Inline `style={}` only for dynamic values (widths, computed colors)
- React Flow overrides use `!important` in global CSS and `!` prefix in Tailwind

## Key Domain Concepts

- **NetworkPolicy**: namespace-scoped Calico policy (`projectcalico.org/v3`)
- **GlobalNetworkPolicy**: cluster-scoped Calico policy
- **Rule categories**: rules are classified as `outsideCluster`, `inNamespace`, or `inCluster`
  based on CIDR ranges (RFC 1918 / CGNAT / link-local) and selectors
- **Actions**: `Allow` (green), `Deny` (red), `Log` (amber), `Pass` (blue)
- **ResolvedPolicy**: parsed + normalized policy object used throughout the app

## Adding New Features

1. New Calico fields → update `types/calico.ts`, then `yamlParser.ts`, `policyToGraph.ts`, `policyExplainer.ts`
2. New node types → add component in `components/Visualization/nodes/`, register in `PolicyFlow.tsx` `nodeTypes`
3. New edge types → add component in `components/Visualization/edges/`, register in `PolicyFlow.tsx` `edgeTypes`
4. New rule categories → update `RuleCategory` type in `graph.ts` and `classifyRule()` in `policyToGraph.ts`

## Common Pitfalls

- `verbatimModuleSyntax` will fail the build if you use `import { SomeType }` without `type`
- React Flow nodes must be registered in the `nodeTypes` object outside the component (not inline)
- Tailwind v4 has no config file — customization is CSS-based (`@theme` in CSS)
- The app has no router; do not add route-based code splitting
- Sample YAML is embedded as strings in `samples/index.ts` (not loaded from files at runtime)
