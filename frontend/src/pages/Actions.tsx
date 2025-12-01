import { useState, useEffect } from 'react'
import { CheckCircle, XCircle, RotateCcw, Clock, AlertTriangle, ChevronDown, ChevronUp, ExternalLink, Shield, Target, User, MapPin, Activity, FileText, Brain, TrendingUp } from 'lucide-react'
import { actionService } from '../services/api'
import { wsService } from '../services/websocket'
import type { Action, ThreatContext } from '../types'
import { formatDistanceToNow } from 'date-fns'

export default function Actions() {
  const [pendingActions, setPendingActions] = useState<Action[]>([])
  const [actionHistory, setActionHistory] = useState<Action[]>([])
  const [activeTab, setActiveTab] = useState<'pending' | 'history'>('pending')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()

    // Listen for action updates
    const unsubscribe = wsService.on('action_approved', () => {
      loadData()
    })

    return () => {
      unsubscribe()
    }
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [pending, history] = await Promise.all([
        actionService.getPending(),
        actionService.getHistory(50),
      ])
      // threat_context is now extracted in the API
      const enrichedPending = pending
      const enrichedHistory = history
      setPendingActions(enrichedPending)
      setActionHistory(enrichedHistory)
    } catch (error) {
      console.error('Error loading actions:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleApprove = async (actionId: string) => {
    try {
      await actionService.approve(actionId, 'dashboard_user', 'Approved from dashboard')
      await loadData()
    } catch (error) {
      console.error('Error approving action:', error)
      alert('Failed to approve action')
    }
  }

  const handleReject = async (actionId: string) => {
    try {
      await actionService.reject(actionId, 'dashboard_user', 'Rejected from dashboard')
      await loadData()
    } catch (error) {
      console.error('Error rejecting action:', error)
      alert('Failed to reject action')
    }
  }

  const handleRollback = async (actionId: string) => {
    try {
      await actionService.rollback(actionId, 'Rolled back from dashboard')
      await loadData()
    } catch (error) {
      console.error('Error rolling back action:', error)
      alert('Failed to rollback action')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Action Management</h1>
        <p className="mt-1 text-sm text-gray-500">
          Review and manage security actions with detailed threat context
        </p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('pending')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'pending'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Pending Approval ({pendingActions.length})
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'history'
                ? 'border-primary-500 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Action History ({actionHistory.length})
          </button>
        </nav>
      </div>

      {/* Content */}
      {loading ? (
        <div className="text-center py-12">
          <div className="text-gray-500">Loading actions...</div>
        </div>
      ) : activeTab === 'pending' ? (
        <PendingActionsList
          actions={pendingActions}
          onApprove={handleApprove}
          onReject={handleReject}
        />
      ) : (
        <ActionHistoryList
          actions={actionHistory}
          onRollback={handleRollback}
        />
      )}
    </div>
  )
}

function PendingActionsList({
  actions,
  onApprove,
  onReject,
}: {
  actions: Action[]
  onApprove: (id: string) => void
  onReject: (id: string) => void
}) {
  if (actions.length === 0) {
    return (
      <div className="card text-center py-12">
        <CheckCircle className="h-12 w-12 text-success-400 mx-auto mb-4" />
        <p className="text-gray-500">No pending actions</p>
        <p className="text-sm text-gray-400 mt-2">
          All actions have been reviewed
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {actions.map((action) => (
        <EnhancedActionCard
          key={action.action_id}
          action={action}
          onApprove={onApprove}
          onReject={onReject}
        />
      ))}
    </div>
  )
}

function ActionHistoryList({
  actions,
  onRollback,
}: {
  actions: Action[]
  onRollback: (id: string) => void
}) {
  if (actions.length === 0) {
    return (
      <div className="card text-center py-12">
        <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <p className="text-gray-500">No action history</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {actions.map((action) => (
        <div key={action.action_id} className="card">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-3">
                <span
                  className={`badge ${
                    action.status === 'completed'
                      ? 'badge-success'
                      : action.status === 'rejected'
                      ? 'badge-danger'
                      : action.status === 'rolled_back'
                      ? 'badge-warning'
                      : 'badge-info'
                  }`}
                >
                  {action.status.toUpperCase()}
                </span>
                <span
                  className={`badge ${
                    action.tier === 'red'
                      ? 'badge-danger'
                      : action.tier === 'yellow'
                      ? 'badge-warning'
                      : 'badge-success'
                  }`}
                >
                  {action.tier.toUpperCase()}
                </span>
                <span className="font-semibold text-gray-900">{action.type}</span>
                {action.executed_at && (
                  <span className="text-sm text-gray-500">
                    {formatDistanceToNow(new Date(action.executed_at), {
                      addSuffix: true,
                    })}
                  </span>
                )}
              </div>
              <p className="text-gray-700 mb-2">{action.description}</p>
              {action.executed_by && (
                <p className="text-xs text-gray-500">
                  Executed by: {action.executed_by}
                </p>
              )}
            </div>
            {action.status === 'completed' &&
              action.rollback_info?.can_rollback && (
                <button
                  onClick={() => onRollback(action.action_id)}
                  className="btn-secondary ml-4"
                >
                  <RotateCcw className="h-4 w-4 mr-2 inline" />
                  Rollback
                </button>
              )}
          </div>
        </div>
      ))}
    </div>
  )
}

function EnhancedActionCard({
  action,
  onApprove,
  onReject,
}: {
  action: Action
  onApprove: (id: string) => void
  onReject: (id: string) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const threatContext = action.threat_context

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-danger-600 bg-danger-50 border-danger-200'
      case 'high':
        return 'text-danger-600 bg-danger-50 border-danger-200'
      case 'medium':
        return 'text-warning-600 bg-warning-50 border-warning-200'
      default:
        return 'text-success-600 bg-success-50 border-success-200'
    }
  }

  const getTimelineColor = (status: string) => {
    switch (status) {
      case 'critical':
        return 'border-danger-500 bg-danger-50'
      case 'danger':
        return 'border-danger-400 bg-danger-50'
      case 'warning':
        return 'border-warning-400 bg-warning-50'
      default:
        return 'border-gray-300 bg-gray-50'
    }
  }

  return (
    <div className="card border-l-4 border-l-danger-500 hover:shadow-lg transition-all">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="flex items-center space-x-3 mb-2">
            <span className={`badge badge-danger`}>
              {action.tier.toUpperCase()}
            </span>
            <span className="font-semibold text-gray-900 text-lg">{action.type.replace('_', ' ').toUpperCase()}</span>
            <span className="text-sm text-gray-500">
              {formatDistanceToNow(new Date(action.executed_at || Date.now()), { addSuffix: true })}
            </span>
          </div>
          
          {threatContext && (
            <div className="mt-3">
              <div className={`inline-flex items-center space-x-2 px-3 py-1.5 rounded-md border ${getSeverityColor(threatContext.severity)}`}>
                <AlertTriangle className="h-4 w-4" />
                <span className="font-semibold text-sm">{threatContext.severity.toUpperCase()}</span>
                <span className="text-sm">-</span>
                <span className="font-medium text-sm">{threatContext.threat_type}</span>
                <span className="text-sm">Detected</span>
              </div>
              <div className="flex items-center space-x-4 mt-2 text-sm text-gray-600">
                <span>Confidence: <span className="font-semibold text-gray-900">{Math.round(threatContext.confidence * 100)}%</span></span>
                <span>MITRE ATT&CK: <span className="font-semibold text-gray-900">{threatContext.mitre_technique}</span></span>
              </div>
            </div>
          )}
        </div>
        
        <div className="ml-4 flex space-x-2">
          <button
            onClick={() => onApprove(action.action_id)}
            className="btn-primary"
          >
            <CheckCircle className="h-4 w-4 mr-2 inline" />
            Approve
          </button>
          <button
            onClick={() => onReject(action.action_id)}
            className="btn-secondary"
          >
            <XCircle className="h-4 w-4 mr-2 inline" />
            Reject
          </button>
        </div>
      </div>

      {/* Description */}
      <p className="text-gray-700 mb-4">{action.description}</p>

      {/* Threat Details - Collapsible */}
      {threatContext && (
        <>
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between py-2 px-3 bg-gray-50 rounded-md hover:bg-gray-100 transition-colors mb-4"
          >
            <span className="text-sm font-semibold text-gray-700">
              {expanded ? 'Hide' : 'Show'} Threat Details
            </span>
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>

          {expanded && (
            <div className="space-y-4 border-t border-gray-200 pt-4">
              {/* Attack Details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div className="flex items-start space-x-2">
                    <Target className="h-5 w-5 text-gray-400 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Target System</p>
                      <p className="text-sm font-medium text-gray-900">{threatContext.target_system}</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-2">
                    <MapPin className="h-5 w-5 text-gray-400 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Affected Resource</p>
                      <p className="text-sm font-medium text-gray-900">{threatContext.affected_resource}</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-2">
                    <User className="h-5 w-5 text-gray-400 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Compromised User</p>
                      <p className="text-sm font-medium text-gray-900">
                        {threatContext.affected_user}
                        {threatContext.user_email && (
                          <span className="text-gray-500 ml-2">({threatContext.user_email})</span>
                        )}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="flex items-start space-x-2">
                    <Activity className="h-5 w-5 text-gray-400 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Source IP</p>
                      <p className="text-sm font-medium text-gray-900">{threatContext.source_ip}</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-2">
                    <Shield className="h-5 w-5 text-gray-400 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Attack Vector</p>
                      <p className="text-sm font-medium text-gray-900">{threatContext.attack_vector}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Timeline */}
              {threatContext.timeline && threatContext.timeline.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                    <Clock className="h-4 w-4 mr-2" />
                    What Happened (Timeline)
                  </h3>
                  <div className="space-y-2">
                    {threatContext.timeline.map((event, idx) => (
                      <div
                        key={idx}
                        className={`flex items-start space-x-3 p-3 rounded-md border-l-4 ${getTimelineColor(event.status)}`}
                      >
                        <span className="font-mono text-xs font-semibold text-gray-600 min-w-[60px]">
                          {event.time}
                        </span>
                        <span className="text-sm text-gray-700 flex-1">{event.event}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk Assessment */}
              {threatContext.risk_assessment && (
                <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                    <AlertTriangle className="h-4 w-4 mr-2 text-warning-600" />
                    Risk Assessment
                  </h3>
                  <div className="space-y-2 text-sm">
                    <p><span className="font-semibold">Risk:</span> {threatContext.risk_assessment.risk}</p>
                    <p><span className="font-semibold">Data at Risk:</span> {threatContext.risk_assessment.data_at_risk}</p>
                    <p><span className="font-semibold">Compliance:</span> {threatContext.risk_assessment.compliance}</p>
                    <p><span className="font-semibold">Estimated Impact:</span> {threatContext.risk_assessment.impact}</p>
                  </div>
                </div>
              )}

              {/* AI Reasoning */}
              {threatContext.ai_reasoning && (
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                    <Brain className="h-4 w-4 mr-2" />
                    AI Reasoning (RAG Context)
                  </h3>
                  <div className="bg-primary-50 border border-primary-200 rounded-lg p-4">
                    <p className="text-sm text-gray-700 leading-relaxed">{threatContext.ai_reasoning}</p>
                  </div>
                  <div className="mt-3 flex items-center space-x-2 text-xs text-gray-500">
                    <FileText className="h-3 w-3" />
                    <span>Referenced Sources: MITRE ATT&CK {threatContext.mitre_technique}, Internal Incident Database</span>
                  </div>
                </div>
              )}

              {/* Evidence Preview */}
              {threatContext.evidence && (
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                    <FileText className="h-4 w-4 mr-2" />
                    Supporting Evidence
                  </h3>
                  <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                    <div>
                      <p className="text-xs font-semibold text-gray-500 mb-2">Raw Log Entry:</p>
                      <pre className="text-xs text-gray-700 bg-white p-3 rounded border border-gray-200 overflow-x-auto">
                        {JSON.stringify(threatContext.evidence.raw_log, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-gray-500 mb-2">Anomaly Detection:</p>
                      <ul className="text-xs text-gray-700 space-y-1">
                        {Object.entries(threatContext.evidence.anomaly_detection || {}).map(([key, value]) => (
                          <li key={key}>
                            <span className="font-medium">{key.replace('_', ' ')}:</span> {String(value)}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                  <TrendingUp className="h-4 w-4 mr-2" />
                  Recommended Actions
                </h3>
                <div className="space-y-2">
                  <div className="bg-danger-50 border border-danger-200 rounded-md p-3">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="font-semibold text-sm text-gray-900 mb-1">
                          {action.type.replace('_', ' ').toUpperCase()}
                        </p>
                        <p className="text-xs text-gray-600 mb-2">{action.description}</p>
                        <div className="text-xs text-gray-600 space-y-1">
                          <p>• Impact: {action.type === 'block_ip' ? 'User cannot access from this IP' : 'Action will be executed'}</p>
                          <p>• Reversible: Yes</p>
                          <p>• Risk if wrong: {action.type === 'block_ip' ? 'Legitimate user locked out' : 'Potential service disruption'}</p>
                          <p>• Risk if ignored: Ongoing threat activity</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
