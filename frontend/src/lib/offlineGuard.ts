/**
 * Offline guard. Imported first in main.tsx, before React or anything else can make a request.
 * Patches fetch, XHR, sendBeacon, WebSocket and EventSource so any request to a host other than
 * this origin / localhost / 127.0.0.1 is refused, logged with console.warn, and counted.
 */

type Listener = (count: number) => void

let blocked = 0
const listeners = new Set<Listener>()
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

export function isAllowedUrl(input: string | URL): boolean {
  try {
    const url = new URL(String(input), window.location.href)
    if (url.protocol === 'blob:' || url.protocol === 'data:' || url.protocol === 'about:') return true
    if (url.origin === window.location.origin) return true
    return LOCAL_HOSTS.has(url.hostname)
  } catch {
    return false
  }
}

function record(kind: string, target: string): void {
  blocked += 1
  console.warn(`[ChaosMonkey offline guard] Blocked ${kind} to ${target}. This app never talks to the internet.`)
  listeners.forEach((l) => l(blocked))
}

export function getBlockedCount(): number {
  return blocked
}

export function subscribeBlocked(listener: Listener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

function install(): void {
  if (typeof window === 'undefined' || (window as Window & { __cmGuard?: boolean }).__cmGuard) return
  ;(window as Window & { __cmGuard?: boolean }).__cmGuard = true

  const nativeFetch = window.fetch.bind(window)
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const target = urlOf(input)
    if (!isAllowedUrl(target)) {
      record('fetch', target)
      return Promise.reject(new TypeError('Blocked by ChaosMonkey offline guard'))
    }
    return nativeFetch(input, init)
  }

  const nativeOpen = XMLHttpRequest.prototype.open
  XMLHttpRequest.prototype.open = function open(this: XMLHttpRequest, method: string, url: string | URL, ...rest: unknown[]) {
    if (!isAllowedUrl(url)) {
      record('XMLHttpRequest', String(url))
      throw new DOMException('Blocked by ChaosMonkey offline guard', 'SecurityError')
    }
    return (nativeOpen as (...args: unknown[]) => void).call(this, method, url, ...rest)
  } as typeof XMLHttpRequest.prototype.open

  if (navigator.sendBeacon) {
    const nativeBeacon = navigator.sendBeacon.bind(navigator)
    navigator.sendBeacon = (url: string | URL, data?: BodyInit | null) => {
      if (!isAllowedUrl(url)) {
        record('sendBeacon', String(url))
        return false
      }
      return nativeBeacon(url, data)
    }
  }

  const NativeWebSocket = window.WebSocket
  class GuardedWebSocket extends NativeWebSocket {
    constructor(url: string | URL, protocols?: string | string[]) {
      const http = String(url).replace(/^ws/, 'http')
      if (!isAllowedUrl(http)) {
        record('WebSocket', String(url))
        throw new DOMException('Blocked by ChaosMonkey offline guard', 'SecurityError')
      }
      super(url, protocols)
    }
  }
  window.WebSocket = GuardedWebSocket

  if (window.EventSource) {
    const NativeEventSource = window.EventSource
    class GuardedEventSource extends NativeEventSource {
      constructor(url: string | URL, init?: EventSourceInit) {
        if (!isAllowedUrl(url)) {
          record('EventSource', String(url))
          throw new DOMException('Blocked by ChaosMonkey offline guard', 'SecurityError')
        }
        super(url, init)
      }
    }
    window.EventSource = GuardedEventSource
  }
}

install()
