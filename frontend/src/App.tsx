import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import InvestigationOverview from './pages/InvestigationOverview'
import InvestigationPlaceholder from './pages/InvestigationPlaceholder'
import HostsPage from './pages/HostsPage'
import FlowsPage from './pages/FlowsPage'
import DetectionsPage from './pages/DetectionsPage'
import DetectionDetailPage from './pages/DetectionDetailPage'
import NotFoundPage from './pages/NotFoundPage'
import UploadPage from './pages/UploadPage'
import TimelinePage from './pages/TimelinePage'
import IocsPage from './pages/IocsPage'
import DnsPage from './pages/DnsPage'
import HttpPage from './pages/HttpPage'

export function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route element={<UploadPage />} path="/" />
          <Route element={<InvestigationOverview />} path="/investigations/:id" />
          <Route element={<HostsPage />} path="/investigations/:id/hosts" />
          <Route element={<FlowsPage />} path="/investigations/:id/connections" />
          <Route element={<FlowsPage />} path="/investigations/:id/flows" />
          <Route element={<DnsPage />} path="/investigations/:id/dns" />
          <Route element={<HttpPage />} path="/investigations/:id/http" />
          <Route element={<DetectionsPage />} path="/investigations/:id/detections" />
          <Route element={<DetectionDetailPage />} path="/investigations/:id/detections/:detectionId" />
          <Route element={<TimelinePage />} path="/investigations/:id/timeline" />
          <Route element={<IocsPage />} path="/investigations/:id/iocs" />
          <Route element={<InvestigationPlaceholder />} path="/investigations/:id/:section" />
          <Route element={<NotFoundPage />} path="*" />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App
