import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle, Clock, TrendingUp } from 'lucide-react'
import { threatService, systemService } from '../services/api'
import { wsService } from '../services/websocket'
import type { Threat, SystemStatus } from '../types'
import ThreatCard from '../components/ThreatCard'
import StatsCard from '../components/StatsCard'
import SimulationControls from '../components/SimulationControls'
import { formatDistanceToNow } from 'date-fns'

export default function Dashboard() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null)
  const [stats, setStats] = useState({
    totalDetected: 0,
    highPriority: 0,
    autoExecuted: 0,
    pendingApproval: 0,
  })
  const [newThreatIds, setNewThreatIds] = useState<Set<string>>(new Set())
  const threatsRef = useRef<Threat[]>([])

  useEffect(() => {
    // Load initial data
    loadThreats()
    loadSystemStatus()
    loadStats()

    // Set up WebSocket listeners
    const unsubscribeThreat = wsService.on('threat_detected', (event) => {
      const newThreat = event.data as Threat
      // Mark as new for animation
      setNewThreatIds((prev) => new Set([...prev, newThreat.alert_id]))
      // Remove animation class after 3 seconds
      setTimeout(() => {
        setNewThreatIds((prev) => {
          const next = new Set(prev)
          next.delete(newThreat.alert_id)
          return next
        })
      }, 3000)
      
      setThreats((prev) => {
        // Check if threat already exists (avoid duplicates)
        const exists = prev.some(t => t.alert_id === newThreat.alert_id)
        if (exists) return prev
        return [newThreat, ...prev]
      })
      updateStats()
    })

    const unsubscribeAction = wsService.on('action_executed', () => {
      updateStats()
    })

    // Poll for updates every 30 seconds
    const interval = setInterval(() => {
      loadThreats()
      loadStats()
    }, 30000)

    return () => {
      unsubscribeThreat()
      unsubscribeAction()
      clearInterval(interval)
    }
  }, [])

  const loadThreats = async () => {
    try {
      const data = await threatService.getAll(20)
      setThreats(data)
    } catch (error) {
      console.error('Error loading threats:', error)
    }
  }

  const loadSystemStatus = async () => {
    try {
      const status = await systemService.getStatus()
      setSystemStatus(status)
    } catch (error) {
      console.error('Error loading system status:', error)
    }
  }

  const loadStats = async () => {
    try {
      // Calculate stats from threats
      const allThreats = await threatService.getAll(100)
      const highPriority = allThreats.filter(
        (t) => t.severity === 'high' || t.severity === 'critical'
      ).length
      const autoExecuted = allThreats.reduce(
        (sum, t) => sum + (t.executed_actions?.length || 0),
        0
      )
      const pendingApproval = allThreats.reduce(
        (sum, t) => sum + (t.pending_actions?.length || 0),
        0
      )

      setStats({
        totalDetected: allThreats.length,
        highPriority,
        autoExecuted,
        pendingApproval,
      })
    } catch (error) {
      console.error('Error loading stats:', error)
    }
  }

  const updateStats = () => {
    loadStats()
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'text-danger-600'
      case 'medium':
        return 'text-warning-600'
      default:
        return 'text-success-600'
    }
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.9) return 'text-danger-600'
    if (confidence >= 0.7) return 'text-warning-600'
    return 'text-success-600'
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">
          Real-time threat detection and autonomous mitigation
        </p>
      </div>

      {/* Simulation Controls */}
      <SimulationControls />

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Events Detected"
          value={stats.totalDetected}
          icon={TrendingUp}
          color="primary"
        />
        <StatsCard
          title="High Priority"
          value={stats.highPriority}
          icon={AlertTriangle}
          color="danger"
        />
        <StatsCard
          title="Auto-Executed"
          value={stats.autoExecuted}
          icon={CheckCircle}
          color="success"
        />
        <StatsCard
          title="Pending Approval"
          value={stats.pendingApproval}
          icon={Clock}
          color="warning"
        />
      </div>

      {/* System Status */}
      {systemStatus && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">System Status</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(systemStatus.agents).map(([name, status]) => (
              <div key={name} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 capitalize">
                  {name.replace('_', ' ')}
                </span>
                <span
                  className={`badge ${
                    status.status === 'operational'
                      ? 'badge-success'
                      : 'badge-warning'
                  }`}
                >
                  {status.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Threats */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">
              Active Threats
            </h2>
            <p className="text-sm text-gray-500 mt-1">Real-time security events and alerts</p>
          </div>
          <div className="flex items-center space-x-3">
            <span className="badge badge-info">
              {threats.length} Active
            </span>
            <Link
              to="/analytics"
              className="text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              View All →
            </Link>
          </div>
        </div>

        {threats.length === 0 ? (
          <div className="card text-center py-12">
            <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No threats detected</p>
            <p className="text-sm text-gray-400 mt-2">
              System is monitoring for suspicious activity...
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {threats.map((threat) => (
              <div
                key={threat.alert_id}
                className={`transition-all duration-500 ${
                  newThreatIds.has(threat.alert_id)
                    ? 'animate-slide-in-right opacity-100'
                    : 'opacity-100'
                }`}
                style={{
                  animation: newThreatIds.has(threat.alert_id)
                    ? 'slideInRight 0.5s ease-out'
                    : undefined,
                }}
              >
                <ThreatCard threat={threat} />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}



