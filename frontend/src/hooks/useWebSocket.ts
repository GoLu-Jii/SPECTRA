import { useEffect, useRef, useCallback } from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import { dataProvider } from '../services/api';
import { normalizeBackendAlert } from '../services/api/realApi';
import { WebSocketLike } from '../types';

export function useWebSocket(onAlertReceived?: (alert: any) => void) {
  const socketRef = useRef<WebSocketLike | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const retryCountRef = useRef(0);
  const shouldReconnectRef = useRef(true);
  
  const prependAlert = useSpectraStore((s) => s.prependAlert);
  const setConnectionStatus = useSpectraStore((s) => s.setConnectionStatus);
  const simulatedOffline = useSpectraStore((s) => s.simulatedOffline);
  const health = useSpectraStore((s) => s.health);
  const isSystemLoading = useSpectraStore((s) => s.isSystemLoading);

  const connect = useCallback(() => {
    shouldReconnectRef.current = true;

    if (simulatedOffline || isSystemLoading || health?.ready !== true) {
      setConnectionStatus('disconnected');
      return;
    }

    setConnectionStatus('connecting');

    try {
      const ws = dataProvider.createWebSocketConnection('/ws');
      socketRef.current = ws;

      ws.onopen = () => {
        setConnectionStatus('connected');
        retryCountRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const rawData = JSON.parse(event.data);
          // Handle both direct alert objects and wrapped { type: 'alert', data: alert } messages
          const alertObj = normalizeBackendAlert(rawData.data || rawData);

          if (alertObj) {
            prependAlert(alertObj);
            if (onAlertReceived) {
              onAlertReceived(alertObj);
            }
          }
        } catch (e) {
          console.error('[WebSocket] Error parsing incoming alert JSON:', e);
        }
      };

      ws.onerror = (_err) => {
        setConnectionStatus('error');
      };

      ws.onclose = () => {
        setConnectionStatus('disconnected');
        socketRef.current = null;

        if (!shouldReconnectRef.current || retryCountRef.current >= 6) {
          if (retryCountRef.current >= 6) setConnectionStatus('error');
          return;
        }

        // Bounded exponential backoff avoids an aggressive reconnect loop.
        const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 16000);
        retryCountRef.current++;

        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, delay);
      };
    } catch (err) {
      console.error('[WebSocket] Failed to instantiate socket connection:', err);
      setConnectionStatus('error');
    }
  }, [prependAlert, setConnectionStatus, simulatedOffline, isSystemLoading, health?.ready, onAlertReceived]);

  useEffect(() => {
    connect();

    return () => {
      shouldReconnectRef.current = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [connect]);

  const reconnect = useCallback(() => {
    shouldReconnectRef.current = false;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (socketRef.current) {
      socketRef.current.close();
    }
    retryCountRef.current = 0;
    connect();
  }, [connect]);

  return { reconnect };
}
