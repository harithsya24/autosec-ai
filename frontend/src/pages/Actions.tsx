import { useState, useEffect } from 'react'
import { CheckCircle, XCircle, RotateCcw, Clock } from 'lucide-react'
import { actionService } from '../services/api'
import { wsService } from '../services/websocket'
import type { Action } from '../types'
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
      setPendingActions(pending)
      setActionHistory(history)
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
        <h1 className="text-3xl font-bold text-gray-900">Action Management</h1>
        <p className="mt-2 text-gray-600">
          Review and manage security actions
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
    <div className="space-y-4">
      {actions.map((action) => (
        <div key={action.action_id} className="card">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-3">
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
                <span className="text-sm text-gray-500">
                  {formatDistanceToNow(new Date(action.executed_at || Date.now()), {
                    addSuffix: true,
                  })}
                </span>
              </div>
              <p className="text-gray-700 mb-3">{action.description}</p>
              {Object.keys(action.parameters).length > 0 && (
                <div className="bg-gray-50 rounded-lg p-3 mb-3">
                  <p className="text-xs font-medium text-gray-500 mb-2">Parameters:</p>
                  <pre className="text-xs text-gray-700">
                    {JSON.stringify(action.parameters, null, 2)}
                  </pre>
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
        </div>
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

