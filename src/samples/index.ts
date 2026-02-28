export interface SamplePolicy {
  id: string;
  name: string;
  description: string;
  category: string;
  yaml: string;
}

export const SAMPLE_CATEGORIES = [
  'Baseline / Zero Trust',
  'Kubernetes NetworkPolicy',
  'Pod & Namespace Scoping',
  'Database & Stateful Workloads',
  'Gateway API & Ingress Controller',
  'Egress Control & Internet Access',
  'Port & Protocol Restrictions',
  'ServiceAccount-Aware Policies (Calico-Specific)',
  'GlobalNetworkPolicy & Cluster Protection',
  'Production Reference Architectures',
];

export const SAMPLE_POLICIES: SamplePolicy[] = [
  // ── Baseline / Zero Trust ──────────────────────────────────────────
  {
    id: 'default-deny-all',
    name: 'default-deny-all',
    description: 'Denies all ingress and egress traffic for pods in a namespace (zero-trust baseline).',
    category: 'Baseline / Zero Trust',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  selector: all()
  types:
    - Ingress
    - Egress`,
  },
  {
    id: 'k8s-default-deny-ingress',
    name: 'k8s-default-deny-ingress',
    description: 'Kubernetes NetworkPolicy that isolates ingress for all pods in a namespace.',
    category: 'Kubernetes NetworkPolicy',
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress`,
  },
  {
    id: 'k8s-allow-cross-namespace-web',
    name: 'k8s-allow-cross-namespace-web',
    description: 'Allows ingress on 8080 from frontend pods in namespaces labeled team=web.',
    category: 'Kubernetes NetworkPolicy',
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              team: web
          podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080`,
  },
  {
    id: 'k8s-egress-ipblock-range',
    name: 'k8s-egress-ipblock-range',
    description: 'Allows TCP egress to a CIDR on a target port range using endPort.',
    category: 'Kubernetes NetworkPolicy',
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-port-range
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: db-client
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/24
            except:
              - 10.0.0.10/32
      ports:
        - protocol: TCP
          port: 32000
          endPort: 32768`,
  },

  // ── Pod & Namespace Scoping ────────────────────────────────────────
  {
    id: 'allow-app-to-app-same-namespace',
    name: 'allow-app-to-app-same-namespace',
    description: 'Allows traffic only between pods with matching labels in one namespace.',
    category: 'Pod & Namespace Scoping',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-app-to-app-same-namespace
  namespace: production
spec:
  selector: app == 'web'
  types:
    - Ingress
    - Egress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app == 'api'
      destination:
        ports:
          - 8080
  egress:
    - action: Allow
      protocol: TCP
      destination:
        selector: app == 'api'
        ports:
          - 8080`,
  },
  {
    id: 'allow-cross-namespace-by-label',
    name: 'allow-cross-namespace-by-label',
    description: 'Allows ingress from pods in another namespace using pod + namespace selectors.',
    category: 'Pod & Namespace Scoping',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-cross-namespace-by-label
  namespace: backend
spec:
  selector: app == 'api-server'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app == 'frontend'
        namespaceSelector: team == 'web'
      destination:
        ports:
          - 443`,
  },
  {
    id: 'allow-namespace-to-namespace',
    name: 'allow-namespace-to-namespace',
    description: 'Allows all traffic from one namespace to another (e.g., app to db namespace).',
    category: 'Pod & Namespace Scoping',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-namespace-to-namespace
  namespace: database
spec:
  selector: all()
  types:
    - Ingress
  ingress:
    - action: Allow
      source:
        namespaceSelector: "projectcalico.org/name == 'application'"`,
  },

  // ── Database & Stateful Workloads ──────────────────────────────────
  {
    id: 'allow-db-access-from-app-namespace',
    name: 'allow-db-access-from-app-namespace',
    description: 'Allows application namespace to access DB pods on database ports only.',
    category: 'Database & Stateful Workloads',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-db-access-from-app-namespace
  namespace: database
spec:
  selector: role == 'database'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: role == 'app-server'
        namespaceSelector: "projectcalico.org/name == 'application'"
      destination:
        ports:
          - 5432
          - 3306`,
  },

  // ── Gateway API & Ingress Controller ──────────────────────────────
  {
    id: 'only-allow-ingress-nginx',
    name: 'only-allow-ingress-nginx',
    description: 'Allows ingress traffic only from ingress-nginx namespace pods.',
    category: 'Gateway API & Ingress Controller',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: only-allow-ingress-nginx
  namespace: production
spec:
  selector: app == 'web'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app == 'ingress-nginx'
        namespaceSelector: "projectcalico.org/name == 'ingress-nginx'"
      destination:
        ports:
          - 8080`,
  },
  {
    id: 'deny-direct-pod-access',
    name: 'deny-direct-pod-access',
    description: 'Denies all ingress except from the ingress controller, forcing traffic through the gateway.',
    category: 'Gateway API & Ingress Controller',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: deny-direct-pod-access
  namespace: production
spec:
  selector: app == 'web'
  order: 100
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        namespaceSelector: "projectcalico.org/name == 'ingress-nginx'"
      destination:
        ports:
          - 8080
    - action: Deny`,
  },
  {
    id: 'allow-ingress-nginx-egress',
    name: 'allow-ingress-nginx-egress',
    description: 'Restricts application pod egress to only the ingress-nginx services.',
    category: 'Gateway API & Ingress Controller',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-ingress-nginx-egress
  namespace: production
spec:
  selector: app == 'web'
  types:
    - Egress
  egress:
    - action: Allow
      protocol: TCP
      destination:
        selector: app == 'ingress-nginx'
        namespaceSelector: "projectcalico.org/name == 'ingress-nginx'"
        ports:
          - 80
          - 443`,
  },
  {
    id: 'gateway-api-allow-traffic',
    name: 'gateway-api-allow-traffic',
    description: 'Allows backend pods to receive HTTPS traffic from Gateway API controller pods.',
    category: 'Gateway API & Ingress Controller',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: gateway-api-allow-traffic
  namespace: production
spec:
  selector: app == 'backend'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app.kubernetes.io/component == 'gateway'
        namespaceSelector: "projectcalico.org/name == 'gateway-system'"
      destination:
        ports:
          - 443`,
  },
  {
    id: 'gateway-api-default-deny-with-exception',
    name: 'gateway-api-default-deny-with-exception',
    description: 'Default deny all ingress with explicit allow only from Gateway API on port 443.',
    category: 'Gateway API & Ingress Controller',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: gateway-api-default-deny-with-exception
  namespace: production
spec:
  selector: app == 'backend'
  order: 100
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app.kubernetes.io/component == 'gateway'
        namespaceSelector: "projectcalico.org/name == 'gateway-system'"
      destination:
        ports:
          - 443
    - action: Deny`,
  },
  {
    id: 'gateway-api-cross-namespace-routing',
    name: 'gateway-api-cross-namespace-routing',
    description: 'Allows Gateway API traffic from gateway-system namespace to backend in production namespace.',
    category: 'Gateway API & Ingress Controller',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: gateway-api-cross-namespace-routing
  namespace: production
spec:
  selector: app == 'web'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        namespaceSelector: "projectcalico.org/name == 'gateway-system'"
      destination:
        ports:
          - 443`,
  },

  // ── Egress Control & Internet Access ───────────────────────────────
  {
    id: 'allow-dns-only',
    name: 'allow-dns-only',
    description: 'Allows egress only to DNS (TCP/UDP 53); required for name resolution.',
    category: 'Egress Control & Internet Access',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-dns-only
  namespace: production
spec:
  selector: all()
  types:
    - Egress
  egress:
    - action: Allow
      protocol: UDP
      destination:
        ports:
          - 53
    - action: Allow
      protocol: TCP
      destination:
        ports:
          - 53`,
  },
  {
    id: 'allow-kubernetes-api',
    name: 'allow-kubernetes-api',
    description: 'Allows egress to the Kubernetes API server endpoint (port 6443).',
    category: 'Egress Control & Internet Access',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-kubernetes-api
  namespace: production
spec:
  selector: app == 'controller'
  types:
    - Egress
  egress:
    - action: Allow
      protocol: TCP
      destination:
        nets:
          - 10.96.0.1/32
        ports:
          - 6443`,
  },
  {
    id: 'allow-internet-access',
    name: 'allow-internet-access',
    description: 'Allows egress to 0.0.0.0/0 for unrestricted public internet access.',
    category: 'Egress Control & Internet Access',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-internet-access
  namespace: production
spec:
  selector: app == 'external-client'
  types:
    - Egress
  egress:
    - action: Allow
      destination:
        nets:
          - 0.0.0.0/0`,
  },
  {
    id: 'allow-internet-except-private',
    name: 'allow-internet-except-private',
    description: 'Allows internet egress but denies RFC 1918 / private networks.',
    category: 'Egress Control & Internet Access',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-internet-except-private
  namespace: production
spec:
  selector: app == 'saas-connector'
  types:
    - Egress
  egress:
    - action: Allow
      destination:
        nets:
          - 0.0.0.0/0
        notNets:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16`,
  },
  {
    id: 'allow-specific-external-ips',
    name: 'allow-specific-external-ips',
    description: 'Allows egress only to approved external IPs or CIDR ranges.',
    category: 'Egress Control & Internet Access',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-specific-external-ips
  namespace: production
spec:
  selector: app == 'payment-gateway'
  types:
    - Egress
  egress:
    - action: Allow
      protocol: TCP
      destination:
        nets:
          - 203.0.113.0/24
          - 198.51.100.10/32
        ports:
          - 443`,
  },
  {
    id: 'allow-egress-to-service',
    name: 'allow-egress-to-service',
    description: 'Allows egress only to a specific Kubernetes service (kube-dns). Uses Calico service match.',
    category: 'Egress Control & Internet Access',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-egress-to-service
  namespace: production
spec:
  selector: app == 'backend'
  types:
    - Egress
  egress:
    - action: Allow
      protocol: UDP
      destination:
        services:
          name: kube-dns
          namespace: kube-system
        ports:
          - 53
    - action: Allow
      protocol: TCP
      destination:
        services:
          name: redis-master
          namespace: cache
        ports:
          - 6379`,
  },

  // ── Port & Protocol Restrictions ───────────────────────────────────
  {
    id: 'allow-specific-tcp-ports',
    name: 'allow-specific-tcp-ports',
    description: 'Allows ingress traffic only on approved TCP ports (80, 443, 5432).',
    category: 'Port & Protocol Restrictions',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-specific-tcp-ports
  namespace: production
spec:
  selector: app == 'multi-service'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      destination:
        ports:
          - 80
          - 443
          - 5432`,
  },
  {
    id: 'allow-udp-only',
    name: 'allow-udp-only',
    description: 'Restricts all ingress traffic to UDP protocol only (e.g., DNS or game server).',
    category: 'Port & Protocol Restrictions',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-udp-only
  namespace: production
spec:
  selector: app == 'dns-server'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: UDP
      destination:
        ports:
          - 53
    - action: Deny`,
  },
  {
    id: 'allow-metrics-port',
    name: 'allow-metrics-port',
    description: 'Allows access only to Prometheus metrics ports (9090/9091) from the monitoring namespace.',
    category: 'Port & Protocol Restrictions',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-metrics-port
  namespace: production
spec:
  selector: has(app)
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        namespaceSelector: "projectcalico.org/name == 'monitoring'"
      destination:
        ports:
          - 9090
          - 9091`,
  },

  // ── ServiceAccount-Aware Policies (Calico-Specific) ────────────────
  {
    id: 'allow-k8s-api-by-serviceaccount',
    name: 'allow-k8s-api-by-serviceaccount',
    description: 'Allows Kubernetes API access only for pods running under specific ServiceAccounts.',
    category: 'ServiceAccount-Aware Policies (Calico-Specific)',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-k8s-api-by-serviceaccount
  namespace: production
spec:
  serviceAccountSelector: "projectcalico.org/name == 'api-controller'"
  types:
    - Egress
  egress:
    - action: Allow
      protocol: TCP
      destination:
        nets:
          - 10.96.0.1/32
        ports:
          - 6443`,
  },
  {
    id: 'allow-db-by-serviceaccount',
    name: 'allow-db-by-serviceaccount',
    description: 'Restricts database ingress to workloads running under approved ServiceAccounts.',
    category: 'ServiceAccount-Aware Policies (Calico-Specific)',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-db-by-serviceaccount
  namespace: database
spec:
  selector: role == 'database'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        serviceAccounts:
          names:
            - backend-api
            - migration-runner
      destination:
        ports:
          - 5432`,
  },
  {
    id: 'allow-ingress-by-ingress-sa',
    name: 'allow-ingress-by-ingress-sa',
    description: 'Allows ingress traffic only from the ingress controller ServiceAccount.',
    category: 'ServiceAccount-Aware Policies (Calico-Specific)',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-ingress-by-ingress-sa
  namespace: production
spec:
  selector: app == 'web'
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        serviceAccounts:
          selector: "role == 'ingress-controller'"
        namespaceSelector: "projectcalico.org/name == 'ingress-nginx'"
      destination:
        ports:
          - 8080`,
  },

  // ── GlobalNetworkPolicy & Cluster Protection ───────────────────────
  {
    id: 'gnp-protect-kubernetes-api',
    name: 'gnp-protect-kubernetes-api',
    description: 'Restricts kube-apiserver access to authorized CIDRs and control-plane nodes.',
    category: 'GlobalNetworkPolicy & Cluster Protection',
    yaml: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: protect-kubernetes-api
spec:
  order: 10
  selector: has(node-role.kubernetes.io/control-plane)
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        nets:
          - 10.0.0.0/8
      destination:
        ports:
          - 6443
    - action: Allow
      protocol: TCP
      source:
        selector: has(node-role.kubernetes.io/control-plane)
      destination:
        ports:
          - 6443
    - action: Deny
      protocol: TCP
      destination:
        ports:
          - 6443`,
  },
  {
    id: 'gnp-lock-down-control-plane',
    name: 'gnp-lock-down-control-plane',
    description: 'Protects etcd, kubelet, and control-plane ports from unauthorized access.',
    category: 'GlobalNetworkPolicy & Cluster Protection',
    yaml: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: lock-down-control-plane
spec:
  order: 5
  selector: has(node-role.kubernetes.io/control-plane)
  types:
    - Ingress
  ingress:
    # Allow etcd peer traffic between control-plane nodes
    - action: Allow
      protocol: TCP
      source:
        selector: has(node-role.kubernetes.io/control-plane)
      destination:
        ports:
          - 2379
          - 2380
    # Allow kubelet API from control-plane nodes
    - action: Allow
      protocol: TCP
      source:
        selector: has(node-role.kubernetes.io/control-plane)
      destination:
        ports:
          - 10250
    # Allow kube-apiserver
    - action: Allow
      protocol: TCP
      destination:
        ports:
          - 6443
    # Allow localhost
    - action: Allow
      destination:
        nets:
          - 127.0.0.0/8
    # Deny everything else to control-plane ports
    - action: Deny
      protocol: TCP
      destination:
        ports:
          - 2379
          - 2380
          - 10250
          - 10259
          - 10257`,
  },

  // ── Production Reference Architectures ─────────────────────────────
  {
    id: 'secure-web-application',
    name: 'secure-web-application',
    description: 'Web app reachable only via ingress, DB access restricted, controlled egress.',
    category: 'Production Reference Architectures',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: secure-web-application
  namespace: production
spec:
  selector: app == 'web'
  types:
    - Ingress
    - Egress
  ingress:
    # Only accept traffic from ingress controller
    - action: Allow
      protocol: TCP
      source:
        namespaceSelector: "projectcalico.org/name == 'ingress-nginx'"
      destination:
        ports:
          - 8080
    - action: Deny
  egress:
    # Allow DNS resolution
    - action: Allow
      protocol: UDP
      destination:
        ports:
          - 53
    # Allow access to backend API
    - action: Allow
      protocol: TCP
      destination:
        selector: app == 'api'
        ports:
          - 8443
    # Allow access to database
    - action: Allow
      protocol: TCP
      destination:
        selector: role == 'database'
        namespaceSelector: "projectcalico.org/name == 'database'"
        ports:
          - 5432
    - action: Deny`,
  },
  {
    id: 'secure-ci-runner',
    name: 'secure-ci-runner',
    description: 'CI runner with kube-api, container registry, and limited internet access.',
    category: 'Production Reference Architectures',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: secure-ci-runner
  namespace: ci
spec:
  selector: app == 'ci-runner'
  types:
    - Ingress
    - Egress
  ingress:
    # Only allow CI controller to reach runners
    - action: Allow
      protocol: TCP
      source:
        selector: app == 'ci-controller'
      destination:
        ports:
          - 8089
    - action: Deny
  egress:
    # DNS resolution
    - action: Allow
      protocol: UDP
      destination:
        ports:
          - 53
    # Kubernetes API
    - action: Allow
      protocol: TCP
      destination:
        nets:
          - 10.96.0.1/32
        ports:
          - 6443
    # Container registry
    - action: Allow
      protocol: TCP
      destination:
        nets:
          - 10.96.0.0/16
        ports:
          - 443
    # Limited internet (HTTPS only, no private nets)
    - action: Allow
      protocol: TCP
      destination:
        nets:
          - 0.0.0.0/0
        notNets:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
        ports:
          - 443
    - action: Deny`,
  },
  {
    id: 'secure-vault-deployment',
    name: 'secure-vault-deployment',
    description: 'Vault with peer replication, restricted client access, and metrics exposure.',
    category: 'Production Reference Architectures',
    yaml: `apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: secure-vault-deployment
  namespace: vault
spec:
  selector: app == 'vault'
  types:
    - Ingress
    - Egress
  ingress:
    # Vault peer replication (raft)
    - action: Allow
      protocol: TCP
      source:
        selector: app == 'vault'
      destination:
        ports:
          - 8201
    # Client API access from application namespaces
    - action: Allow
      protocol: TCP
      source:
        namespaceSelector: "environment == 'production'"
      destination:
        ports:
          - 8200
    # Prometheus metrics scraping
    - action: Allow
      protocol: TCP
      source:
        namespaceSelector: "projectcalico.org/name == 'monitoring'"
      destination:
        ports:
          - 8200
    - action: Deny
  egress:
    # DNS resolution
    - action: Allow
      protocol: UDP
      destination:
        ports:
          - 53
    # Vault peer traffic
    - action: Allow
      protocol: TCP
      destination:
        selector: app == 'vault'
        ports:
          - 8201
    # Backend storage (Consul or etcd)
    - action: Allow
      protocol: TCP
      destination:
        selector: app == 'consul'
        ports:
          - 8500
          - 8501
    - action: Deny`,
  },
];
