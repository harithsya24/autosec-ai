import { useState, useEffect } from 'react'
import { Play, Square, Settings, Zap, AlertCircle } from 'lucide-react'
import { simulationService } from '../services/api'

interface SimulationStatus {
  is_running: boolean
  demo_mode: boolean
  config: {
    interval_seconds: number
    enabled_threats: string[]
    auto_clear_low_priority: boolean
    clear_after_seconds: number
  }
  threats_generated: number
  demo_start_time?: string
}

export default function SimulationControls() {
  const [status, setStatus] = useState<SimulationStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [demoDuration, setDemoDuration] = useState(5)
  const [showConfig, setShowConfig] = useState(false)
  const [intervalSeconds, setIntervalSeconds] = useState(45)

  useEffect(() => {
    loadStatus()
    const interval = setInterval(loadStatus, 2000) // Poll every 2 seconds
    return () => clearInterval(interval)
  }, [])

  const loadStatus = async () => {
    try {
      const data = await simulationService.getStatus()
      setStatus(data)
      if (data.config) {
        setIntervalSeconds(data.config.interval_seconds || 45)
      }
    } catch (error) {
      console.error('Error loading simulation status:', error)
    }
  }

  const handleStart = async () => {
    setLoading(true)
    try {
      await simulationService.start()
      await loadStatus()
    } catch (error) {
      console.error('Error starting simulation:', error)
      alert('Failed to start simulation')
    } finally {
      setLoading(false)
    }
  }

  const handleStartDemo = async () => {
    setLoading(true)
    try {
      await simulationService.startDemo(demoDuration)
      await loadStatus()
    } catch (error) {
      console.error('Error starting demo:', error)
      alert('Failed to start demo mode')
    } finally {
      setLoading(false)
    }
  }

  const handleStop = async () => {
    setLoading(true)
    try {
      await simulationService.stop()
      await loadStatus()
    } catch (error) {
      console.error('Error stopping simulation:', error)
      alert('Failed to stop simulation')
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateNext = async () => {
    setLoading(true)
    try {
      await simulationService.generateNextThreat()
      await loadStatus()
    } catch (error) {
      console.error('Error generating threat:', error)
      alert('Failed to generate threat')
    } finally {
      setLoading(false)
    }
  }

  const handleUpdateConfig = async () => {
    setLoading(true)
    try {
      await simulationService.updateConfig({
        interval_seconds: intervalSeconds,
      })
      await loadStatus()
      setShowConfig(false)
    } catch (error) {
      console.error('Error updating config:', error)
      alert('Failed to update configuration')
    } finally {
      setLoading(false)
    }
  }

  if (!status) {
    return (
      <div className="card p-4">
        <p className="text-sm text-gray-500">Loading simulation status...</p>
      </div>
    )
  }

  const isRunning = status.is_running || status.demo_mode

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <AlertCircle className="h-5 w-5 text-warning-600" />
          <h3 className="text-lg font-semibold">Demo Mode - Threat Simulation</h3>
        </div>
        {isRunning && (
          <span className="badge badge-warning animate-pulse">ACTIVE</span>
        )}
      </div>

      <div className="space-y-4">
        {/* Status Info */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-600">Status:</span>
              <span className={`ml-2 font-medium ${
                isRunning ? 'text-success-600' : 'text-gray-400'
              }`}>
                {status.demo_mode ? 'Demo Mode' : status.is_running ? 'Running' : 'Stopped'}
              </span>
            </div>
            <div>
              <span className="text-gray-600">Threats Generated:</span>
              <span className="ml-2 font-medium">{status.threats_generated}</span>
            </div>
            {status.config && (
              <>
                <div>
                  <span className="text-gray-600">Interval:</span>
                  <span className="ml-2 font-medium">{status.config.interval_seconds}s</span>
                </div>
                <div>
                  <span className="text-gray-600">Threat Types:</span>
                  <span className="ml-2 font-medium">{status.config.enabled_threats?.length || 0}</span>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Control Buttons */}
        <div className="flex flex-wrap gap-2">
          {!isRunning ? (
            <>
              <button
                onClick={handleStart}
                disabled={loading}
                className="btn btn-primary flex items-center gap-2"
              >
                <Play className="h-4 w-4" />
                Start Continuous
              </button>
              <button
                onClick={handleStartDemo}
                disabled={loading}
                className="btn btn-warning flex items-center gap-2"
              >
                <Zap className="h-4 w-4" />
                Start Demo (5 min)
              </button>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={demoDuration}
                  onChange={(e) => setDemoDuration(parseInt(e.target.value) || 5)}
                  className="w-16 px-2 py-1 border rounded text-sm"
                />
                <span className="text-sm text-gray-600">min</span>
              </div>
            </>
          ) : (
            <button
              onClick={handleStop}
              disabled={loading}
              className="btn btn-danger flex items-center gap-2"
            >
              <Square className="h-4 w-4" />
              Stop Simulation
            </button>
          )}
          <button
            onClick={handleGenerateNext}
            disabled={loading || !isRunning}
            className="btn btn-secondary flex items-center gap-2"
          >
            <Zap className="h-4 w-4" />
            Generate Next Threat
          </button>
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="btn btn-outline flex items-center gap-2"
          >
            <Settings className="h-4 w-4" />
            Config
          </button>
        </div>

        {/* Configuration Panel */}
        {showConfig && (
          <div className="border-t pt-4 space-y-4">
            <h4 className="font-medium">Simulation Configuration</h4>
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700">
                Threat Interval (seconds)
              </label>
              <input
                type="number"
                min="10"
                max="300"
                value={intervalSeconds}
                onChange={(e) => setIntervalSeconds(parseInt(e.target.value) || 45)}
                className="w-full px-3 py-2 border rounded-md"
              />
              <button
                onClick={handleUpdateConfig}
                disabled={loading}
                className="btn btn-primary btn-sm"
              >
                Update Config
              </button>
            </div>
          </div>
        )}

        {/* Warning Message */}
        <div className="bg-warning-50 border border-warning-200 rounded-lg p-3">
          <p className="text-sm text-warning-800">
            <strong>Demo Mode:</strong> This simulation generates realistic threats for demonstration purposes only.
            All actions are executed in sandbox mode and do not affect production systems.
          </p>
        </div>
      </div>
    </div>
  )
}


