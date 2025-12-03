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
    wsService.connect()
    setWsConnected(true)

    const unsubscribe = wsService.on('action_approved', () => {
      fetch('/api/v1/actions/pending')
        .then((res) => res.json())
        .then((data) => setPendingCount(data.count || 0))
    })

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
      {/* Datadog-style Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50 shadow-sm">
        <div className="w-full px-6">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-3">
                <div className="p-1.5 bg-primary-600 rounded-md">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <h1 className="text-lg font-semibold text-gray-900">AutoSec AI</h1>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              {/* Sandbox Mode Badge */}
              {sandboxMode && (
                <span className="badge badge-warning text-xs">
                  SANDBOX MODE
                </span>
              )}

              {/* Privacy Mode Toggle */}
              <button
                onClick={() => setPrivacyMode(!privacyMode)}
                className="flex items-center space-x-2 px-3 py-1.5 rounded-md border border-gray-300 hover:bg-gray-50 transition-colors text-sm font-medium text-gray-700"
              >
                <Settings className="h-4 w-4" />
                <span>Privacy: {privacyMode ? 'ON' : 'OFF'}</span>
              </button>

              {/* Pending Actions Badge */}
              {pendingCount > 0 && (
                <Link
                  to="/actions"
                  className="relative flex items-center space-x-2 px-3 py-1.5 rounded-md bg-danger-50 text-danger-700 hover:bg-danger-100 transition-colors border border-danger-200 text-sm font-semibold"
                >
                  <Shield className="h-4 w-4" />
                  <span>{pendingCount} Pending</span>
                </Link>
              )}

              {/* WebSocket Status */}
              <div className="flex items-center space-x-2 px-3 py-1.5">
                <div className={`status-dot ${wsConnected ? 'status-dot-success' : 'status-dot-gray'}`} />
                <span className="text-xs font-medium text-gray-600">
                  {wsConnected ? 'Live' : 'Offline'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Datadog-style Sidebar */}
        <aside className="w-64 bg-white border-r border-gray-200 min-h-[calc(100vh-3.5rem)]">
          <nav className="p-2">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center space-x-3 px-3 py-2.5 rounded-md transition-all mb-1 ${
                    isActive
                      ? 'bg-primary-50 text-primary-700 font-semibold border-l-2 border-primary-600'
                      : 'text-gray-700 hover:bg-gray-50 font-medium'
                  }`}
                >
                  <Icon className={`h-4 w-4 ${isActive ? 'text-primary-600' : 'text-gray-500'}`} />
                  <span className="text-sm">{item.label}</span>
                </Link>
              )
            })}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 bg-gray-50">
          {children}
        </main>
      </div>
    </div>
  )
}



