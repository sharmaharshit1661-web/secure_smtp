import { createContext, useContext } from 'react';

export const PilotContext = createContext(null);

export function usePilot() {
  const identity = useContext(PilotContext);
  return {
    identity,
    canUseLab: identity?.role === 'admin' && identity.lab_enabled === true,
  };
}
