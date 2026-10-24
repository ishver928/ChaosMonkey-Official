import { useEffect, useState } from 'react'

export type Route = 'scan' | 'report' | 'history' | 'rules' | 'settings' | 'about'
const ROUTES: Route[] = ['scan', 'report', 'history', 'rules', 'settings', 'about']

function parse(): Route {
  const r = window.location.hash.replace(/^#\/?/, '').split(/[/?]/)[0] as Route
  return ROUTES.includes(r) ? r : 'scan'
}

export function navigate(route: Route): void {
  if (parse() !== route) window.location.hash = `/${route}`
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(parse)
  useEffect(() => {
    const on = () => {
      setRoute(parse())
      window.scrollTo({ top: 0 })
    }
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return route
}
