import { useEffect, useState } from 'react'

export type Route = 'scan' | 'report' | 'history' | 'rules' | 'settings' | 'about' | 'connected'
const ROUTES: Route[] = ['scan', 'report', 'history', 'rules', 'settings', 'about', 'connected']

function parse(): Route {
  const r = window.location.hash.replace(/^#\/?/, '').split(/[/?]/)[0] as Route
  return ROUTES.includes(r) ? r : 'scan'
}

export function navigate(route: Route): void {
  if (parse() !== route || parseParam()) window.location.hash = `/${route}`
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

function parseParam(): string | null {
  return window.location.hash.replace(/^#\/?/, '').split(/[?]/)[0].split('/')[1] || null
}

/** Second hash segment, e.g. the scan id in `#/report/scan_0123456789abcdef`. */
export function useRouteParam(): string | null {
  const [param, setParam] = useState<string | null>(parseParam)
  useEffect(() => {
    const on = () => setParam(parseParam())
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return param
}
