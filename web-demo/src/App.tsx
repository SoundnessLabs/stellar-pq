import { Routes, Route } from 'react-router-dom'
import { Home } from './pages/Home'
import { VerifierDemo } from './pages/VerifierDemo'
import { SmartAccountDemo } from './pages/SmartAccountDemo'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/verifier" element={<VerifierDemo />} />
      <Route path="/smart-account" element={<SmartAccountDemo />} />
    </Routes>
  )
}

export default App
