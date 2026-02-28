// Policy types for Calico and Kubernetes NetworkPolicy resources.

export type PolicyKind = 'NetworkPolicy' | 'GlobalNetworkPolicy';
export type RuleAction = 'Allow' | 'Deny' | 'Log' | 'Pass';
type PolicyType = 'Ingress' | 'Egress';
type ProtocolName = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'SCTP' | 'UDPLite';
type Protocol = ProtocolName | number;
export type Port = number | string; // number, "range:range", or named port

interface ICMPFields {
  type?: number;
  code?: number;
}

interface ServiceAccountMatch {
  names?: string[];
  selector?: string;
}

interface ServiceMatch {
  name: string;
  namespace: string;
}

export interface EntityRule {
  nets?: string[];
  notNets?: string[];
  selector?: string;
  notSelector?: string;
  namespaceSelector?: string;
  ports?: Port[];
  notPorts?: Port[];
  serviceAccounts?: ServiceAccountMatch;
  services?: ServiceMatch;
}

export interface Rule {
  action: RuleAction;
  protocol?: Protocol;
  notProtocol?: Protocol;
  icmp?: ICMPFields;
  notICMP?: ICMPFields;
  ipVersion?: 4 | 6;
  source?: EntityRule;
  destination?: EntityRule;
  metadata?: {
    annotations?: Record<string, string>;
  };
  http?: {
    methods?: string[];
    paths?: Array<{ exact?: string; prefix?: string }>;
  };
}

interface PolicyMetadata {
  name: string;
  namespace?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface KubernetesLabelSelectorRequirement {
  key: string;
  operator: 'In' | 'NotIn' | 'Exists' | 'DoesNotExist';
  values?: string[];
}

export interface KubernetesLabelSelector {
  matchLabels?: Record<string, string>;
  matchExpressions?: KubernetesLabelSelectorRequirement[];
}

export interface KubernetesIPBlock {
  cidr: string;
  except?: string[];
}

export interface KubernetesNetworkPolicyPeer {
  podSelector?: KubernetesLabelSelector;
  namespaceSelector?: KubernetesLabelSelector;
  ipBlock?: KubernetesIPBlock;
}

export interface KubernetesNetworkPolicyPort {
  protocol?: 'TCP' | 'UDP' | 'SCTP';
  port?: number | string;
  endPort?: number;
}

export interface KubernetesNetworkPolicyIngressRule {
  from?: KubernetesNetworkPolicyPeer[];
  ports?: KubernetesNetworkPolicyPort[];
}

export interface KubernetesNetworkPolicyEgressRule {
  to?: KubernetesNetworkPolicyPeer[];
  ports?: KubernetesNetworkPolicyPort[];
}

export interface KubernetesNetworkPolicySpec {
  podSelector?: KubernetesLabelSelector;
  policyTypes?: PolicyType[];
  ingress?: KubernetesNetworkPolicyIngressRule[];
  egress?: KubernetesNetworkPolicyEgressRule[];
}

interface PolicySpec {
  order?: number;
  tier?: string;
  selector?: string;
  namespaceSelector?: string;
  serviceAccountSelector?: string;
  types?: PolicyType[];
  ingress?: Rule[];
  egress?: Rule[];
  doNotTrack?: boolean;
  preDNAT?: boolean;
  applyOnForward?: boolean;
  performanceHints?: string[];
}

export interface CalicoPolicy {
  apiVersion: string;
  kind: PolicyKind;
  metadata: PolicyMetadata;
  spec: PolicySpec;
}

export interface KubernetesNetworkPolicy {
  apiVersion: string;
  kind: 'NetworkPolicy';
  metadata: PolicyMetadata;
  spec: KubernetesNetworkPolicySpec;
}

export type PolicySource = 'calico' | 'kubernetes';

interface ResolvedPolicyBase {
  apiVersion: string;
  name: string;
  namespace?: string;
  kind: PolicyKind;
  tier: string;
  order?: number;
  selector: string;
  namespaceSelector?: string;
  serviceAccountSelector?: string;
  types: PolicyType[];
  ingressRules: Rule[];
  egressRules: Rule[];
  ingressDefault: 'deny' | 'allow' | 'none';
  egressDefault: 'deny' | 'allow' | 'none';
}

export interface ResolvedCalicoPolicy extends ResolvedPolicyBase {
  raw: CalicoPolicy;
  policySource: 'calico';
}

export interface ResolvedKubernetesPolicy extends ResolvedPolicyBase {
  raw: KubernetesNetworkPolicy;
  policySource: 'kubernetes';
}

// Resolved policy info for visualization
export type ResolvedPolicy = ResolvedCalicoPolicy | ResolvedKubernetesPolicy;
