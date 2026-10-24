import DOMPurify from 'dompurify'

export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} /> // expect: CM-J001
}

export function SafeComment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
}
