import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './reference-theme.css'
import { ThemeProvider } from './context/ThemeContext'
import App from './App.jsx'
import ErrorBoundary from './components/ErrorBoundary'
import './theme.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </ThemeProvider>
  </StrictMode>,
)
