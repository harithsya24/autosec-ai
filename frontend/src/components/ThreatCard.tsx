import { Link } from 'react-router-dom'
import { AlertTriangle, Clock, CheckCircle, Pause } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import type { Threat } from '../types'

interface ThreatCardProps {
  threat: Threat
}

export default function ThreatCard({ threat }: ThreatCardProps) {
  const getSeverityBadge = (severity: string) => {
    const colors = {
      critical: 'badge-danger',
      high: 'badge-danger',
      medium: 'badge-warning',
      low: 'badge-success',
    }
    return colors[severity as keyof typeof colors] || 'badge-info'
  }

  const getConfidenceBadge = (confidence: number) => {
    if (confidence >= 0.9) return 'badge-danger'
    if (confidence >= 0.7) return 'badge-warning'
    return 'badge-success'
  }

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'red':
        return 'text-danger-600 border-danger-200 bg-danger-50'
      case 'yellow':
        return 'text-warning-600 border-warning-200 bg-warning-50'
      case 'green':
        return 'text-success-600 border-success-200 bg-success-50'
      default:
        return 'text-gray-600 border-gray-200 bg-gray-50'
    }
  }

  return (
    <div className="card hover:shadow-md transition-all border-l-4 border-l-primary-500">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          {/* Header */}
          <div className="flex items-center space-x-2 mb-3 flex-wrap gap-2">
            <span className={`badge ${getSeverityBadge(threat.severity)}`}>
              {threat.severity.toUpperCase()}
            </span>
            <span className={`badge ${getConfidenceBadge(threat.confidence)}`}>
              {Math.round(threat.confidence * 100)}% Confidence
            </span>
            {threat.pending_actions && threat.pending_actions.length > 0 && (
              <span className="badge badge-warning">
                REQUIRES APPROVAL
              </span>
            )}
            {threat.matched_techniques && threat.matched_techniques.length > 0 && (
              <span className="badge badge-gray">
                {threat.matched_techniques[0]}
              </span>
            )}
          </div>

          {/* Title */}
          <h3 className="text-base font-semibold text-gray-900 mb-2">
            {threat.threat_type}
          </h3>

          {/* Description */}
          <p className="text-gray-600 text-sm mb-4 leading-relaxed">{threat.description}</p>

          {/* Details */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 text-sm">
            <div>
              <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Target</span>
              <p className="font-semibold text-gray-900 mt-1 text-sm">
                {threat.affected_resources[0] || 'N/A'}
              </p>
            </div>
            {threat.anomaly_score && (
              <div>
                <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Anomaly Score</span>
                <p className="font-semibold text-gray-900 mt-1 text-sm">
                  {threat.anomaly_score.toFixed(2)}
                </p>
              </div>
            )}
            <div>
              <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Detected</span>
              <p className="font-semibold text-gray-900 mt-1 text-sm">
                {formatDistanceToNow(new Date(threat.timestamp), {
                  addSuffix: true,
                })}
              </p>
            </div>
            <div>
              <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Alert ID</span>
              <p className="font-mono text-xs text-gray-600 mt-1">
                {threat.alert_id.slice(0, 12)}...
              </p>
            </div>
          </div>

          {/* Actions Status */}
          {threat.recommended_actions && threat.recommended_actions.length > 0 && (
            <div className="mt-4 pt-4 border-t border-gray-200">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">
                Recommended Actions
              </p>
              <div className="space-y-2">
                {threat.executed_actions?.map((action) => (
                  <div
                    key={action.action_id}
                    className="flex items-center space-x-2 text-sm bg-success-50 border border-success-200 rounded-md p-2"
                  >
                    <CheckCircle className="h-4 w-4 text-success-600 flex-shrink-0" />
                    <span className="text-gray-700 flex-1">
                      <span className={`font-semibold ${getTierColor(action.tier)}`}>
                        {action.tier.toUpperCase()}
                      </span>{' '}
                      - {action.description}
                    </span>
                    <span className="text-xs text-success-600 font-medium">
                      AUTO-EXECUTED
                    </span>
                  </div>
                ))}
                {threat.pending_actions?.map((action) => (
                  <div
                    key={action.action_id}
                    className="flex items-center space-x-2 text-sm bg-warning-50 border border-warning-200 rounded-md p-2"
                  >
                    <Pause className="h-4 w-4 text-warning-600 flex-shrink-0" />
                    <span className="text-gray-700 flex-1">
                      <span className={`font-semibold ${getTierColor(action.tier)}`}>
                        {action.tier.toUpperCase()}
                      </span>{' '}
                      - {action.description}
                    </span>
                    <span className="text-xs text-warning-600 font-medium">
                      PENDING
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="ml-4 flex flex-col space-y-2 min-w-[140px]">
          <Link
            to={`/threats/${threat.alert_id}`}
            className="btn-primary text-sm text-center"
          >
            View Details
          </Link>
          {threat.pending_actions && threat.pending_actions.length > 0 && (
            <Link
              to="/actions"
              className="btn-secondary text-sm text-center"
            >
              Review Actions
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}



