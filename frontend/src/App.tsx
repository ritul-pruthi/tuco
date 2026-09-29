import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import InvestigationOverview from './pages/InvestigationOverview'
import InvestigationPlaceholder from './pages/InvestigationPlaceholder'
import NotFoundPage from './pages/NotFoundPage'
import UploadPage from './pages/UploadPage'

export function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route element={<UploadPage />} path="/" />
          <Route element={<InvestigationOverview />} path="/investigations/:id" />
          <Route element={<InvestigationPlaceholder />} path="/investigations/:id/:section" />
          <Route element={<NotFoundPage />} path="*" />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App
