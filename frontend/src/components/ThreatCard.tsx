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
    <div className="card hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          {/* Header */}
          <div className="flex items-center space-x-3 mb-3">
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
          </div>

          {/* Title */}
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            {threat.threat_type}
          </h3>

          {/* Description */}
          <p className="text-gray-600 text-sm mb-4">{threat.description}</p>

          {/* Details */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 text-sm">
            <div>
              <span className="text-gray-500">Target:</span>
              <p className="font-medium text-gray-900">
                {threat.affected_resources[0] || 'N/A'}
              </p>
            </div>
            {threat.anomaly_score && (
              <div>
                <span className="text-gray-500">Anomaly Score:</span>
                <p className="font-medium text-gray-900">
                  {threat.anomaly_score.toFixed(2)}
                </p>
              </div>
            )}
            <div>
              <span className="text-gray-500">Detected:</span>
              <p className="font-medium text-gray-900">
                {formatDistanceToNow(new Date(threat.timestamp), {
                  addSuffix: true,
                })}
              </p>
            </div>
            {threat.matched_techniques && threat.matched_techniques.length > 0 && (
              <div>
                <span className="text-gray-500">MITRE:</span>
                <p className="font-medium text-gray-900">
                  {threat.matched_techniques[0]}
                </p>
              </div>
            )}
          </div>

          {/* Actions Status */}
          {threat.recommended_actions && threat.recommended_actions.length > 0 && (
            <div className="mt-4 pt-4 border-t border-gray-200">
              <p className="text-sm font-medium text-gray-700 mb-2">
                Recommended Actions:
              </p>
              <div className="space-y-2">
                {threat.executed_actions?.map((action) => (
                  <div
                    key={action.action_id}
                    className="flex items-center space-x-2 text-sm"
                  >
                    <CheckCircle className="h-4 w-4 text-success-600" />
                    <span className="text-gray-700">
                      <span className={`font-medium ${getTierColor(action.tier)}`}>
                        {action.tier.toUpperCase()}
                      </span>{' '}
                      - {action.description}
                    </span>
                    <span className="text-xs text-gray-500">
                      (AUTO-EXECUTED)
                    </span>
                  </div>
                ))}
                {threat.pending_actions?.map((action) => (
                  <div
                    key={action.action_id}
                    className="flex items-center space-x-2 text-sm"
                  >
                    <Pause className="h-4 w-4 text-warning-600" />
                    <span className="text-gray-700">
                      <span className={`font-medium ${getTierColor(action.tier)}`}>
                        {action.tier.toUpperCase()}
                      </span>{' '}
                      - {action.description}
                    </span>
                    <span className="text-xs text-warning-600">
                      (WAITING APPROVAL)
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="ml-4 flex flex-col space-y-2">
          <Link
            to={`/threats/${threat.alert_id}`}
            className="btn-primary text-sm"
          >
            View Details
          </Link>
          {threat.pending_actions && threat.pending_actions.length > 0 && (
            <Link
              to="/actions"
              className="btn-secondary text-sm"
            >
              Review Actions
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}


