// The offline guard must load before anything else can make a request.
import './lib/offlineGuard'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { consumeOpenParam } from './lib/plugin'

// Claude Code plugin deep links may arrive as ?open=/report/<id>; move them into the hash route.
consumeOpenParam()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
