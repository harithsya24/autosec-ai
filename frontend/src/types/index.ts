export interface Threat {
  alert_id: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
  threat_type: string
  description: string
  timestamp: string
  affected_resources: string[]
  anomaly_score?: number
  matched_techniques?: string[]
  recommended_actions?: Action[]
  executed_actions?: Action[]
  pending_actions?: Action[]
  threat_analysis?: ThreatAnalysis
}

export interface ThreatAnalysis {
  explanation: string
  retrieved_context: RetrievedContext[]
  reasoning_chain: ReasoningStep[]
  confidence_breakdown: ConfidenceBreakdown
}

export interface RetrievedContext {
  id: string
  title: string
  description: string
  source: string
  similarity: number
  type: 'mitre' | 'cve' | 'incident'
}

export interface ReasoningStep {
  step: number
  name: string
  description: string
  model?: string
  result: string
  duration_ms?: number
}

export interface ConfidenceBreakdown {
  anomaly_score: number
  rag_quality: number
  source_diversity: number
  quality_distribution: number
  overall: number
}

export interface Action {
  action_id: string
  type: string
  tier: 'green' | 'yellow' | 'red'
  status: 'pending' | 'completed' | 'rejected' | 'rolled_back'
  description: string
  parameters: Record<string, any>
  executed_at?: string
  executed_by?: string
  rollback_info?: RollbackInfo
  requires_approval: boolean
}

export interface RollbackInfo {
  can_rollback: boolean
  rollback_method?: string
  rollback_parameters?: Record<string, any>
}

export interface SystemStatus {
  status: string
  agents: {
    log_analyzer: AgentStatus
    threat_intelligence: AgentStatus
    response_agent: AgentStatus
    action_executor: AgentStatus
  }
  timestamp: string
}

export interface AgentStatus {
  status: string
  last_activity?: string
  model_loaded?: boolean
}

export interface ComplianceReport {
  report_id: string
  type: 'soc2' | 'gdpr' | 'hipaa' | 'custom'
  period_start: string
  period_end: string
  generated_at: string
  summary: string
  sections: ComplianceSection[]
  metrics: ComplianceMetrics
}

export interface ComplianceSection {
  title: string
  content: string
  findings: string[]
  recommendations: string[]
}

export interface ComplianceMetrics {
  total_incidents: number
  incidents_resolved: number
  false_positives: number
  average_response_time: number
  actions_taken: number
  actions_approved: number
  actions_rejected: number
}

