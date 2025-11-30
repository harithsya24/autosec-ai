import { Link, useLocation } from 'react-router-dom'
import { Shield, Activity, FileText, BarChart3, Settings } from 'lucide-react'
import { useState, useEffect } from 'react'
import { wsService } from '../services/websocket'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const [sandboxMode, setSandboxMode] = useState(true)
  const [privacyMode, setPrivacyMode] = useState(true)
  const [pendingCount, setPendingCount] = useState(0)
  const [wsConnected, setWsConnected] = useState(false)

  useEffect(() => {
    // Connect WebSocket
    wsService.connect()
    setWsConnected(true)

    // Listen for action updates
    const unsubscribe = wsService.on('action_approved', () => {
      // Refresh pending count
      fetch('/api/v1/actions/pending')
        .then((res) => res.json())
        .then((data) => setPendingCount(data.count || 0))
    })

    // Initial pending count
    fetch('/api/v1/actions/pending')
      .then((res) => res.json())
      .then((data) => setPendingCount(data.count || 0))

    return () => {
      unsubscribe()
      wsService.disconnect()
    }
  }, [])

  const navItems = [
    { path: '/', label: 'Dashboard', icon: Activity },
    { path: '/actions', label: 'Actions', icon: Shield },
    { path: '/analytics', label: 'Analytics', icon: BarChart3 },
    { path: '/compliance', label: 'Compliance', icon: FileText },
  ]

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Shield className="h-8 w-8 text-primary-600" />
              <h1 className="text-xl font-bold text-gray-900">AutoSec AI</h1>
            </div>

            <div className="flex items-center space-x-4">
              {/* Sandbox Mode Badge */}
              {sandboxMode && (
                <span className="badge badge-warning">
                  Sandbox Mode: ON
                </span>
              )}

              {/* Privacy Mode Toggle */}
              <button
                onClick={() => setPrivacyMode(!privacyMode)}
                className="flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-gray-300 hover:bg-gray-50 transition-colors"
              >
                <Settings className="h-4 w-4" />
                <span className="text-sm font-medium">
                  Privacy: {privacyMode ? 'ON' : 'OFF'}
                </span>
              </button>

              {/* Pending Actions Badge */}
              {pendingCount > 0 && (
                <Link
                  to="/actions"
                  className="relative flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-danger-50 text-danger-700 hover:bg-danger-100 transition-colors"
                >
                  <Shield className="h-4 w-4" />
                  <span className="text-sm font-medium">{pendingCount} Pending</span>
                </Link>
              )}

              {/* WebSocket Status */}
              <div className="flex items-center space-x-2">
                <div
                  className={`h-2 w-2 rounded-full ${
                    wsConnected ? 'bg-success-500' : 'bg-gray-400'
                  }`}
                />
                <span className="text-xs text-gray-500">
                  {wsConnected ? 'Live' : 'Offline'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-white border-r border-gray-200 min-h-[calc(100vh-4rem)]">
          <nav className="p-4 space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-primary-50 text-primary-700 font-medium'
                      : 'text-gray-700 hover:bg-gray-50'
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {children}
        </main>
      </div>
    </div>
  )
}


