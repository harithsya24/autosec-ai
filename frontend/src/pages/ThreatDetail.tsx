import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ExternalLink, CheckCircle, Clock, AlertTriangle } from 'lucide-react'
import { threatService, actionService } from '../services/api'
import type { Threat, Action } from '../types'
import { formatDistanceToNow } from 'date-fns'

export default function ThreatDetail() {
  const { id } = useParams<{ id: string }>()
  const [threat, setThreat] = useState<Threat | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (id) {
      loadThreat()
    }
  }, [id])

  const loadThreat = async () => {
    try {
      const data = await threatService.getById(id!)
      setThreat(data)
    } catch (error) {
      console.error('Error loading threat:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading threat details...</div>
      </div>
    )
  }

  if (!threat) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <p className="text-gray-500">Threat not found</p>
        <Link to="/" className="text-primary-600 hover:text-primary-700 mt-4 inline-block">
          Back to Dashboard
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <Link
          to="/"
          className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
        >
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex-1">
          <div className="flex items-center space-x-3 mb-2">
            <h1 className="text-3xl font-bold text-gray-900">{threat.threat_type}</h1>
            <span className={`badge ${
              threat.severity === 'critical' || threat.severity === 'high' 
                ? 'badge-danger' 
                : threat.severity === 'medium' 
                ? 'badge-warning' 
                : 'badge-success'
            }`}>
              {threat.severity.toUpperCase()}
            </span>
            <span className={`badge ${
              threat.confidence >= 0.9 
                ? 'badge-danger' 
                : threat.confidence >= 0.7 
                ? 'badge-warning' 
                : 'badge-success'
            }`}>
              {Math.round(threat.confidence * 100)}% Confidence
            </span>
          </div>
          <p className="text-gray-600">
            Detected {formatDistanceToNow(new Date(threat.timestamp), { addSuffix: true })}
          </p>
        </div>
      </div>

      {/* Threat Overview */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Threat Overview</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-gray-500">Source IP</p>
            <p className="font-medium text-gray-900">
              {threat.affected_resources?.[0]?.split('/')[0] || 'Unknown'}
            </p>
          </div>
          {threat.anomaly_score && (
            <div>
              <p className="text-sm text-gray-500">Anomaly Score</p>
              <p className="font-medium text-gray-900">
                {threat.anomaly_score.toFixed(3)}
              </p>
            </div>
          )}
          {threat.matched_techniques && threat.matched_techniques.length > 0 && (
            <div>
              <p className="text-sm text-gray-500">MITRE Techniques</p>
              <p className="font-medium text-gray-900">
                {threat.matched_techniques.join(', ')}
              </p>
            </div>
          )}
          {threat.affected_resources && threat.affected_resources.length > 0 && (
            <div>
              <p className="text-sm text-gray-500">Affected Resources</p>
              <p className="font-medium text-gray-900 text-sm">
                {threat.affected_resources[0]}
              </p>
            </div>
          )}
        </div>
        {threat.description && (
          <div className="mt-4 pt-4 border-t border-gray-200">
            <p className="text-sm text-gray-500 mb-2">Description</p>
            <p className="text-gray-700">{threat.description}</p>
          </div>
        )}
      </div>

      {/* Threat Analysis */}
      {threat.threat_analysis && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">AI Reasoning Chain</h2>
          {threat.threat_analysis.reasoning_chain && threat.threat_analysis.reasoning_chain.length > 0 ? (
            <div className="space-y-4">
              {threat.threat_analysis.reasoning_chain.map((step, idx) => (
              <div key={idx} className="border-l-4 border-primary-500 pl-4">
                <div className="flex items-center space-x-2 mb-2">
                  <span className="font-semibold text-gray-900">Step {step.step}: {step.name}</span>
                  {step.duration_ms && (
                    <span className="text-xs text-gray-500">
                      ({step.duration_ms}ms)
                    </span>
                  )}
                </div>
                <p className="text-gray-700 text-sm mb-1">{step.description}</p>
                {step.model && (
                  <p className="text-xs text-gray-500">Model: {step.model}</p>
                )}
                <p className="text-gray-600 text-sm mt-2">{step.result}</p>
              </div>
              ))}
            </div>
          ) : (
            <div className="text-gray-500 text-sm">
              Reasoning chain not available for this threat.
            </div>
          )}
        </div>
      )}

      {/* Retrieved Context */}
      {threat.threat_analysis?.retrieved_context && threat.threat_analysis.retrieved_context.length > 0 ? (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Retrieved Context (RAG)</h2>
          <div className="space-y-3">
            {threat.threat_analysis.retrieved_context.map((context, idx) => (
              <div
                key={idx}
                className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="font-medium text-gray-900">{context.title}</h3>
                    <p className="text-xs text-gray-500 mt-1">
                      {context.type.toUpperCase()} • Similarity: {Math.round(context.similarity * 100)}%
                    </p>
                  </div>
                  {context.source && (
                    <a
                      href={context.source}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary-600 hover:text-primary-700"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  )}
                </div>
                <p className="text-sm text-gray-700">{context.description}</p>
              </div>
            ))}
          </div>
        </div>
      ) : threat.threat_analysis && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Retrieved Context (RAG)</h2>
          <div className="text-gray-500 text-sm">
            No retrieved context available for this threat.
          </div>
        </div>
      )}

      {/* Confidence Breakdown */}
      {threat.threat_analysis?.confidence_breakdown ? (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Confidence Breakdown</h2>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-600">Anomaly Score</span>
                <span className="font-medium">
                  {Math.round(threat.threat_analysis.confidence_breakdown.anomaly_score * 100)}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-primary-600 h-2 rounded-full"
                  style={{
                    width: `${threat.threat_analysis.confidence_breakdown.anomaly_score * 100}%`,
                  }}
                />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-600">RAG Quality</span>
                <span className="font-medium">
                  {Math.round(threat.threat_analysis.confidence_breakdown.rag_quality * 100)}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-success-600 h-2 rounded-full"
                  style={{
                    width: `${threat.threat_analysis.confidence_breakdown.rag_quality * 100}%`,
                  }}
                />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-600">Source Diversity</span>
                <span className="font-medium">
                  {Math.round(threat.threat_analysis.confidence_breakdown.source_diversity * 100)}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-warning-600 h-2 rounded-full"
                  style={{
                    width: `${threat.threat_analysis.confidence_breakdown.source_diversity * 100}%`,
                  }}
                />
              </div>
            </div>
            <div className="pt-3 border-t border-gray-200">
              <div className="flex justify-between text-sm mb-1">
                <span className="font-semibold text-gray-900">Overall Confidence</span>
                <span className="font-bold text-lg">
                  {Math.round(threat.threat_analysis.confidence_breakdown.overall * 100)}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-primary-600 h-2 rounded-full"
                  style={{
                    width: `${threat.threat_analysis.confidence_breakdown.overall * 100}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Confidence Breakdown</h2>
          <div className="text-gray-500 text-sm">
            Confidence breakdown not available. Overall confidence: {Math.round(threat.confidence * 100)}%
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Recommended Actions</h2>
        {((threat.executed_actions && threat.executed_actions.length > 0) || 
          (threat.pending_actions && threat.pending_actions.length > 0)) ? (
          <div className="space-y-4">
            {threat.executed_actions && threat.executed_actions.length > 0 && (
              <>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Executed Actions</h3>
                {threat.executed_actions.map((action) => (
                  <ActionItem key={action.action_id} action={action} executed />
                ))}
              </>
            )}
            {threat.pending_actions && threat.pending_actions.length > 0 && (
              <>
                <h3 className="text-sm font-medium text-gray-700 mb-2 mt-4">Pending Approval</h3>
                {threat.pending_actions.map((action) => (
                  <ActionItem key={action.action_id} action={action} />
                ))}
              </>
            )}
          </div>
        ) : (
          <div className="text-gray-500 text-sm">
            No actions recommended for this threat.
          </div>
        )}
      </div>

      {/* Additional Details */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Additional Details</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-500">Alert ID</p>
            <p className="font-mono text-sm text-gray-900">{threat.alert_id}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Detection Timestamp</p>
            <p className="text-sm text-gray-900">
              {new Date(threat.timestamp).toLocaleString()}
            </p>
          </div>
          {threat.matched_techniques && threat.matched_techniques.length > 0 && (
            <div>
              <p className="text-sm text-gray-500">MITRE ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-2 mt-1">
                {threat.matched_techniques.map((tech) => (
                  <a
                    key={tech}
                    href={`https://attack.mitre.org/techniques/${tech.replace('T', '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="badge badge-info text-xs"
                  >
                    {tech}
                  </a>
                ))}
              </div>
            </div>
          )}
          {threat.affected_resources && threat.affected_resources.length > 0 && (
            <div>
              <p className="text-sm text-gray-500">Affected Resources</p>
              <ul className="text-sm text-gray-900 mt-1 list-disc list-inside">
                {threat.affected_resources.map((resource, idx) => (
                  <li key={idx}>{resource}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ActionItem({ action, executed = false }: { action: Action; executed?: boolean }) {
  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'red':
        return 'border-danger-200 bg-danger-50'
      case 'yellow':
        return 'border-warning-200 bg-warning-50'
      case 'green':
        return 'border-success-200 bg-success-50'
      default:
        return 'border-gray-200 bg-gray-50'
    }
  }

  return (
    <div className={`border rounded-lg p-4 ${getTierColor(action.tier)}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-2">
            {executed ? (
              <CheckCircle className="h-5 w-5 text-success-600" />
            ) : (
              <Clock className="h-5 w-5 text-warning-600" />
            )}
            <span className="font-semibold text-gray-900">
              {action.tier.toUpperCase()} - {action.type}
            </span>
            {executed && (
              <span className="badge badge-success text-xs">AUTO-EXECUTED</span>
            )}
            {!executed && (
              <span className="badge badge-warning text-xs">WAITING APPROVAL</span>
            )}
          </div>
          <p className="text-gray-700 text-sm mb-2">{action.description}</p>
          {action.rollback_info?.can_rollback && (
            <p className="text-xs text-gray-500">
              Rollback available: {action.rollback_info.rollback_method}
            </p>
          )}
        </div>
        {!executed && (
          <div className="ml-4 flex space-x-2">
            <button
              onClick={async () => {
                await actionService.approve(action.action_id, 'user', 'Approved from dashboard')
                window.location.reload()
              }}
              className="btn-primary text-sm"
            >
              Approve
            </button>
            <button
              onClick={async () => {
                await actionService.reject(action.action_id, 'user', 'Rejected from dashboard')
                window.location.reload()
              }}
              className="btn-secondary text-sm"
            >
              Reject
            </button>
          </div>
        )}
        {executed && action.rollback_info?.can_rollback && (
          <button
            onClick={async () => {
              await actionService.rollback(action.action_id, 'Rolled back from dashboard')
              window.location.reload()
            }}
            className="btn-secondary text-sm ml-4"
          >
            Rollback
          </button>
        )}
      </div>
    </div>
  )
}



