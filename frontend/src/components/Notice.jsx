export default function Notice({ children, tone = 'error', onRetry }) {
  return <div className={`ui-notice ui-notice-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
    <span>{children}</span>
    {onRetry && <button type="button" className="btn btn-outline" onClick={onRetry}>Try again</button>}
  </div>;
}
