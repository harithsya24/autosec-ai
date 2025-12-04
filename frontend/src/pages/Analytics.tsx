import { useState, useEffect } from 'react'
import { BarChart3, TrendingUp, AlertTriangle, Shield } from 'lucide-react'
import { threatService } from '../services/api'
import type { Threat } from '../types'
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'

export default function Analytics() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState({
    bySeverity: [] as { name: string; value: number }[],
    byType: [] as { name: string; value: number }[],
    timeline: [] as { date: string; count: number }[],
    confidenceDistribution: [] as { range: string; count: number }[],
  })

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const data = await threatService.getAll(1000)
      setThreats(data)
      calculateStats(data)
    } catch (error) {
      console.error('Error loading analytics:', error)
    } finally {
      setLoading(false)
    }
  }

  const calculateStats = (threatData: Threat[]) => {
    const severityCounts: Record<string, number> = {}
    threatData.forEach((t) => {
      severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1
    })
    const bySeverity = Object.entries(severityCounts).map(([name, value]) => ({
      name: name.toUpperCase(),
      value,
    }))

    const typeCounts: Record<string, number> = {}
    threatData.forEach((t) => {
      typeCounts[t.threat_type] = (typeCounts[t.threat_type] || 0) + 1
    })
    const byType = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, value]) => ({ name, value }))

    const timeline: Record<string, number> = {}
    const now = new Date()
    for (let i = 4; i >= 0; i--) {
      const date = new Date(now)
      date.setDate(date.getDate() - i)
      const dateStr = date.toISOString().split('T')[0]
      timeline[dateStr] = 0
    }
    threatData.forEach((t) => {
      const dateStr = new Date(t.timestamp).toISOString().split('T')[0]
      if (timeline[dateStr] !== undefined) {
        timeline[dateStr]++
      }
    })
    const timelineData = Object.entries(timeline).map(([date, count]) => ({
      date: new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      count,
    }))
    
    const confidenceRanges = [
      { range: '0-50%', min: 0, max: 0.5 },
      { range: '50-70%', min: 0.5, max: 0.7 },
      { range: '70-90%', min: 0.7, max: 0.9 },
      { range: '90-100%', min: 0.9, max: 1.0 },
    ]
    const confidenceDistribution = confidenceRanges.map(({ range, min, max }) => ({
      range,
      count: threatData.filter((t) => t.confidence >= min && t.confidence < max).length,
    }))

    setStats({
      bySeverity,
      byType,
      timeline: timelineData,
      confidenceDistribution,
    })
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading analytics...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Analytics Dashboard</h1>
        <p className="mt-2 text-gray-600">
          Threat detection statistics and trends
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Threats</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">{threats.length}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-danger-500" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">High Priority</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">
                {threats.filter((t) => t.severity === 'high' || t.severity === 'critical').length}
              </p>
            </div>
            <Shield className="h-8 w-8 text-warning-500" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Avg Confidence</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">
                {threats.length > 0
                  ? Math.round(
                      (threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length) * 100
                    )
                  : 0}
                %
              </p>
            </div>
            <TrendingUp className="h-8 w-8 text-success-500" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Actions Executed</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">
                {threats.reduce((sum, t) => sum + (t.executed_actions?.length || 0), 0)}
              </p>
            </div>
            <BarChart3 className="h-8 w-8 text-primary-500" />
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threats by Severity */}
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Threats by Severity</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.bySeverity}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#0ea5e9" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Threats by Type */}
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Top Threat Types</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.byType} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="name" type="category" width={150} />
              <Tooltip />
              <Bar dataKey="value" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Timeline */}
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Threats Over Time (Last 7 Days)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={stats.timeline}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="count" stroke="#0ea5e9" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Confidence Distribution */}
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Confidence Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.confidenceDistribution}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="range" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#22c55e" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}





