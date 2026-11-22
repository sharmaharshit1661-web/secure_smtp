import { useState } from 'react';

export default function useClipboard() {
  const [clipboardError, setClipboardError] = useState('');
  const copyText = async (text, onSuccess) => {
    setClipboardError('');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('unavailable');
      await navigator.clipboard.writeText(text);
      onSuccess?.();
    } catch {
      setClipboardError('Could not copy to the clipboard. Select the text and copy it manually.');
    }
  };
  return { copyText, clipboardError };
}
