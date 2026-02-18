# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.8.2] - 2026-02-18

### Fixed

- **Fixed React error #31 crash when selector fields are objects instead of strings.** When users mistakenly wrote YAML like `namespaceSelector: {namespace: production}` instead of `namespaceSelector: "kubernetes.io/metadata.name == 'production'"`, the app crashed with "Objects are not valid as a React child" error.
  - **Parser sanitization (`yamlParser.ts`):** Extended `sanitizeEntityRule()` to validate `selector`, `notSelector`, `namespaceSelector`, and `serviceAccounts.selector` fields. Non-string values are set to `undefined` to prevent rendering crashes.
  - **Policy-level selector sanitization:** Added `sanitizePolicySelector()` helper and applied it to `spec.selector`, `spec.namespaceSelector`, and `spec.serviceAccountSelector`.
  - **User-friendly warnings:** Added `collectSelectorWarnings()` function that generates helpful messages like "namespaceSelector should be a string, got object. Use namespaceSelector: \"kubernetes.io/metadata.name == 'foo'\" syntax."

### Added (tests)

- **8 new tests** covering selector sanitization:
  - Tests for `namespaceSelector`, `selector`, `notSelector`, and `serviceAccounts.selector` as objects in rule entities.
  - Tests for policy-level `selector`, `namespaceSelector`, and `serviceAccountSelector` as objects.
  - Test confirming valid string selectors pass through without warnings.

## [0.8.1] - 2026-02-10

### Changed

- **Auto-load default deny-all policy on app start.** When the app loads with an empty editor, it now automatically loads the `default-deny-all` sample policy. This provides users with a starting point (zero-trust baseline) that they can paste their own policy over, rather than showing an empty "No policy loaded" state.
  - **Implementation (`AppLayout.tsx`):** Added `useEffect` hook that runs once on component mount. If `state.yamlContent` is empty, it finds the `default-deny-all` policy from `SAMPLE_POLICIES` and calls `loadYaml()` to load it immediately.
  - **Safety check:** The effect only loads the default when the editor is truly empty, preventing it from overwriting user content during React hot reloads or if content was already loaded.

## [0.8.0] - 2026-02-10

### Added

- **Non-intrusive port and CIDR validation.** Invalid port numbers (outside 0-65535) and invalid CIDR notation (e.g., octets > 255, prefix > 32) are now detected and reported without blocking policy parsing or visualization.
  - **Validation logic (`ipUtils.ts`):** Added `isValidPort(port)` to validate numeric ports (0-65535), port ranges ("start:end" with both ends valid and start <= end), and named ports (always valid). Added `isValidCidr(cidr)` to validate IPv4 CIDR notation (x.x.x.x/prefix where each octet is 0-255 and prefix is 0-32).
  - **Parser warnings (`yamlParser.ts`):** Added `collectWarnings()` function that iterates all ingress and egress rules, checking every port in `ports`/`notPorts` and every CIDR in `nets`/`notNets`. Returns human-readable warnings with context (e.g., "Ingress rule 1: destination port 99999 is out of range (0-65535)"). Extended `ParseResult` interface with `warnings: string[]`.
  - **State management (`policyContextDef.ts`):** Added `parseWarnings: string[]` to `PolicyState`. Warnings are dispatched via `SET_POLICY` action and cleared on `SET_ERROR`.
  - **Warning display (`YamlViewer.tsx`):** Added amber warning banner below the YAML editor (above the existing red error banner). Displays each warning as a line with a triangle-exclamation icon.
  - **Visual highlighting in graph (`RuleNode.tsx`):** Invalid ports and CIDRs are rendered in red with a wavy underline decoration in rule cards. Added `PortValue` component for per-port validation display and `CidrList` component for inline CIDR validation. Updated `PortsDisplay`, `CidrEntryCard`, and `DefaultRuleCard` to use the new validation-aware renderers.
  - **Pass-through in layout (`AppLayout.tsx`):** Updated dispatch to include `warnings` from parser result.

### Added (tests)

- **22 new tests** covering validation functions and parser warnings:
  - 19 tests in `ipUtils.test.ts` for `isValidPort()` and `isValidCidr()` covering valid/invalid numeric ports, port ranges, named ports, valid/invalid CIDR notation, octet bounds, prefix bounds, and defensive handling of non-string inputs.
  - 9 tests in `yamlParser.test.ts` for warning generation covering valid ports/CIDRs (no warnings), out-of-range ports, invalid port ranges, invalid notPorts, invalid CIDR notation, invalid prefix lengths, invalid notNets, multi-warning accumulation across rules, and empty warnings on parse errors.

## [0.7.2] - 2026-02-10

### Fixed

- **Fixed blank screen crash when editing YAML with incomplete list items.** When typing incomplete YAML like `nets: - 0.0.0.0/0` followed by `- ` (empty list item), `js-yaml` parses the empty item as `null`. This null value was flowing into downstream code (`policyToGraph`, `explainPolicy`) and causing `TypeError: Cannot read properties of null` crashes, resulting in a blank screen.
  - **Parser sanitization (`yamlParser.ts`):** Added `sanitizeEntityRule()` function to filter out `null`/`undefined` values from entity rule arrays (`nets`, `notNets`, `ports`, `notPorts`, `serviceAccounts.names`) during parsing.
  - **Defensive guards (`ipUtils.ts`):** Added type checks in `cidrContainsIp()` and `coversAllPrivateRanges()` to safely handle non-string CIDR values.
  - **Error handling in components:** Wrapped `policyToGraph()` and `explainPolicy()` calls in try/catch blocks in `PolicyFlow.tsx` and `PolicyExplanation.tsx` to gracefully handle unexpected errors and display error messages in the UI instead of crashing.
  - **React Error Boundary:** Added `ErrorBoundary` component (`src/components/ErrorBoundary.tsx`) to catch unhandled render errors and display a recovery UI with "Try again" button, preventing blank screens from future crashes.

### Added (tests)

- **8 new tests** covering the null-array-elements scenario:
  - 5 tests in `yamlParser.test.ts` for null filtering in `nets`, `notNets`, `ports`, `serviceAccounts.names`, and all-null edge cases.
  - 3 tests in new `ipUtils.test.ts` for defensive guards in `cidrContainsIp` and `coversAllPrivateRanges`.

## [0.7.1] - 2026-02-09

### Added

- **Gateway API sample policies.** Three new sample policies demonstrating secure traffic patterns for Gateway API ingress controllers:
  - `gateway-api-allow-traffic`: Allows backend pods to receive HTTPS traffic from Gateway API controller pods.
  - `gateway-api-default-deny-with-exception`: Default deny all ingress with explicit allow only from Gateway API on port 443.
  - `gateway-api-cross-namespace-routing`: Demonstrates cross-namespace routing with Gateway in gateway-system namespace and backend in production namespace.

### Changed

- **Renamed category:** "Ingress-Only Access Patterns (North-South)" → "Gateway API & Ingress Controller" to better reflect the expanded scope of the policy examples.

## [0.7.0] - 2026-02-09

### Added

- **Service endpoint type in Access Tester.** Users can now test whether traffic to a specific Kubernetes Service would be allowed or denied.
  - New "Service" button in the endpoint type selector (joins IP Address, Pod Labels, Namespace, ServiceAccount).
  - Two new form fields: Service Name and Service Namespace (both required for exact matching).
  - Rule matcher compares user-provided name/namespace against the Calico rule's `services.name` and `services.namespace` fields.
  - Partial matching: providing only a service name (no namespace) shows an indeterminate result with a hint about the required namespace.
  - Works for both ingress (source.services) and egress (destination.services) rules.

- **New sample policy: `allow-egress-to-service`**. Demonstrates using Calico's `destination.services` match to allow egress only to specific cluster services (kube-dns and redis-master), with protocol and port restrictions.

### Changed

- **Rule matcher service resolution now fully functional.** Previously, rules with `services` fields always reported "indeterminate (service resolution not supported)". The matcher now performs exact string matching when a Service endpoint type is selected in the tester.

### Added (tests)

- **9 new test cases for service matching** in `ruleMatcher.test.ts`: exact match, name mismatch, namespace mismatch, partial info handling, no-service-info handling, ingress source services, combined protocol/port matching, port mismatch with service match, and passthrough when rule lacks services constraint.

## [0.6.0] - 2026-02-09

### Added

- **Live-editable YAML editor.** The YAML panel is now a full editor instead of a read-only viewer. Type or paste Calico policy YAML directly and the graph and explanation update as you type.

- **Debounced parsing** (`src/hooks/useDebouncedCallback.ts`). Editor keystrokes update the text immediately; parsing and visualization refresh after 400 ms of inactivity. File imports and example loads bypass the debounce and apply instantly.

- **Preserved visualization during invalid YAML.** When YAML is temporarily broken mid-edit, the last successfully parsed graph and explanation stay visible. An error banner shows the parse issue until the YAML becomes valid again.

### Changed

- **`SET_ERROR` reducer preserves policy state.** Previously, a parse error would clear the policy and rule line ranges from state, removing the graph. The reducer now keeps the last valid policy so the visualization remains stable during editing.

- **`fitView` gated on structural changes.** React Flow's `fitView` now only triggers when the node count changes (rules added or removed), not on every re-parse. This prevents the graph from re-centering on each keystroke.

## [0.5.0] - 2026-02-09

### Added

- **Access Tester panel.** Interactive side panel to test whether specific traffic would be allowed or denied by the loaded policy. Accessible via a "Test Access" button in the header.
  - Support for testing both ingress and egress traffic directions.
  - Multiple endpoint types: IP Address, Pod Labels, Namespace, ServiceAccount.
  - Protocol and port fields available on all endpoint types.
  - Verdict display: Allowed, Denied, Passed to next tier, or Unknown.
  - Rule-by-rule evaluation trace with YAML line highlighting on hover.
  - Resizable right-side panel (260–500px).
  - Disclaimer banner warning this is a best-effort emulation, not a real Calico engine.

- **Full Calico selector expression parser** (`src/lib/matcher/selectorParser.ts`). Recursive-descent parser with tokenizer, AST, and evaluator. Supports: `all()`, `global()`, `has()`, `!`, `==`, `!=`, `in {}`, `not in {}`, `starts with`, `ends with`, `&&`, `||`, and parenthesized grouping.

- **Rule matching engine** (`src/lib/matcher/ruleMatcher.ts`). Tests individual Calico rules against a traffic specification. Handles: nets/notNets (CIDR containment), selector/notSelector (via selector parser), namespaceSelector (with synthetic label inference from namespace name), ports/notPorts (numeric and range), serviceAccounts (name match), protocol/notProtocol. Fields not provided by the user are reported as "indeterminate" rather than assumed.

- **Access testing engine** (`src/lib/matcher/accessTester.ts`). Walks rules in Calico evaluation order (first-match-wins). Allow/Deny are decisive, Log is transparent, Pass reports delegation to next tier. Falls back to implicit default if no rule matches.

- **Shared IP utilities** (`src/lib/ipUtils.ts`). Extracted `ipToNum`, `cidrContainsIp`, `coversAllPrivateRanges` from `policyToGraph.ts` and added `isValidIPv4` and `portMatchesSpec`.

- **Matcher type definitions** (`src/types/matcher.ts`). Types for `TrafficSpec`, `RuleMatchResult`, `FieldMatchDetail`, `RuleTraceEntry`, `AccessTestResult`, `AccessVerdict`, and `EndpointType`.

- **83 new tests** for selector parsing (37), rule matching (28), and access testing (18).

### Fixed

- **CIDR `/0` matching.** `cidrContainsIp` failed to match any IP against `0.0.0.0/0` due to JavaScript bit-shift overflow (`<< 32` wraps to `<< 0`). Added explicit `prefix === 0` guard.

- **Cross-tab field leaking in Access Tester.** Entering a ServiceAccount name, switching to the IP Address tab, and clicking Check Access would include both values. Fixed by gating `buildSpec()` with `switch (endpointType)` so only the active tab's fields are included. Added a Reset button to clear all form state.

- **Pod Labels tab now supports namespaceSelector evaluation.** Rules combining `selector` and `namespaceSelector` (e.g., `role == 'database'` with `projectcalico.org/name == 'database'`) reported "indeterminate" for the namespace selector when using the Pod Labels tab. Added optional Namespace Name and Namespace Labels fields to the Pod Labels tab so users can provide namespace context for complete evaluation.

## [0.4.0] - 2026-02-09

### Added

- **New Examples modal with 24 sample Calico policies.** Replaced the two simple sample buttons with a comprehensive examples browser accessible via an "Examples" button in the header.

- **Categorized policy examples.** Policies are organized into 9 categories with visual icons:
  - Baseline / Zero Trust (default-deny-all)
  - Pod & Namespace Scoping (3 policies)
  - Database & Stateful Workloads (1 policy)
  - Ingress-Only Access Patterns (3 policies)
  - Egress Control & Internet Access (5 policies)
  - Port & Protocol Restrictions (3 policies)
  - ServiceAccount-Aware Policies (3 policies)
  - GlobalNetworkPolicy & Cluster Protection (2 policies)
  - Production Reference Architectures (3 complex multi-rule policies)

- **Native HTML `<dialog>` element for modal.** Uses modern browser APIs for accessibility, backdrop blur, and keyboard navigation (Escape to close).

- **Auto-close on selection.** Clicking any example policy immediately loads it into the editor and closes the modal.

### Changed

- **Header UI refresh.** Replaced the "Samples: [NetworkPolicy] [GlobalNetworkPolicy]" button group with a single prominent indigo-accent "Examples" button with a folder icon.

- **Samples data structure.** Migrated from exporting individual YAML strings to a structured catalog with metadata (id, name, description, category).

### Removed

- Deleted unused `src/samples/networkpolicy.yaml` and `src/samples/globalnetworkpolicy.yaml` files that were not imported at runtime.

## [0.3.0] - 2026-02-07

### Added

- Added support for `namespaceSelector` in GlobalNetworkPolicy rules (was previously only parsed in NetworkPolicy rules).

## [0.2.0] - 2026-02-06

### Fixed

- **Corrected effective default detection for policies with intermediate deny rules.** Previously, when egress rules contained a pattern like "allow specific → deny all LAN → allow internet," the effective default was incorrectly reported as 'allow'. The logic now correctly identifies when restricted deny rules appear before a catch-all allow and reports the effective default as 'deny'.

- **Fixed false positives in unrestricted rule detection.** Rules with protocol restrictions (e.g., `protocol: TCP`) or opposite-side port constraints (e.g., destination ports on ingress rules) were incorrectly classified as "unrestricted" catch-all rules. The detection logic now properly considers these restrictions for both ingress and egress directions.

- **Fixed false positives in broad cluster coverage detection.** The "Everything in the cluster" inference was incorrectly marking rules as broadly covering cluster traffic when they had protocol or port restrictions. This has been corrected to only flag truly unrestricted rules.

- **Fixed opposite-side entity constraints being ignored in rule classification.** Rules with destination nets (e.g., `127.0.0.0/8`), selectors, services, or service accounts on the opposite side were incorrectly classified as unrestricted or broad. All entity fields (nets, ports, selectors, namespace selectors, services, service accounts, and negation fields) are now checked on both sides of a rule for both ingress and egress directions.

### Improved

- Enhanced explanation messages to clarify when the effective default is 'deny' due to intermediate deny rules before a catch-all allow.

- Added comprehensive test coverage for protocol and port-restricted rules in both ingress and egress contexts.

## [0.1.0] - 2026-02-05

### Added

- Initial release of Calico Network Policy Visualizer.
- Interactive visualization of Calico `NetworkPolicy` and `GlobalNetworkPolicy` resources.
- YAML file import with inline error highlighting.
- React Flow-based node/edge diagram showing policy structure.
- Human-readable policy explanations with inferred statuses.
- Support for all Calico rule types (selectors, CIDRs, ports, protocols, services, service accounts).
- Dark theme UI with Tailwind CSS.
