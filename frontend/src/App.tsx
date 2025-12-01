import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import ThreatDetail from './pages/ThreatDetail'
import Actions from './pages/Actions'
import Analytics from './pages/Analytics'
import Compliance from './pages/Compliance'
import Layout from './components/Layout'

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/threats/:id" element={<ThreatDetail />} />
          <Route path="/actions" element={<Actions />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/compliance" element={<Compliance />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App



