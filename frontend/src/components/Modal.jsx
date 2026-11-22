import { useEffect, useRef } from 'react';

export default function Modal({ label, onClose, children }) {
  const ref = useRef(null);
  useEffect(() => {
    const dialog = ref.current;
    const previousFocus = document.activeElement;
    dialog.showModal();
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { dialog.close(); document.body.style.overflow = overflow; previousFocus?.focus?.(); };
  }, []);
  return <dialog ref={ref} className="ui-dialog" aria-label={label} onCancel={event => { event.preventDefault(); onClose(); }} onClick={event => {
    if (event.target === ref.current) {
      const rect = ref.current.getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) onClose();
    }
  }}>{children}</dialog>;
}
