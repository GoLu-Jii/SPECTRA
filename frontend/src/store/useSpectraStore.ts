import { create } from 'zustand';
import { Alert, ConnectionStatus, HealthResponse, StatsResponse } from '../types';
import {
  dataProvider,
  getSimulatedEmptyAlerts,
  getSimulatedNotReady,
  getSimulatedOffline,
  setSimulatedEmptyAlerts,
  setSimulatedNotReady,
  setSimulatedOffline,
} from '../services/api';

interface SpectraState {
  // System & Connection State
  health: HealthResponse | null;
  stats: StatsResponse | null;
  connectionStatus: ConnectionStatus;
  isSystemLoading: boolean;
  systemError: string | null;

  // Alerts State
  alerts: Alert[];
  totalScannedFlows: number; // Derived/tracked for visual packet flow counter
  totalFlaggedThreats: number;

  // Detail Panel State
  selectedAlertId: string | null;
  selectedAlertDetail: Alert | null;
  isDetailLoading: boolean;
  detailError: string | null;

  // Mock Testing Controls
  simulatedOffline: boolean;
  simulatedNotReady: boolean;
  simulatedEmptyAlerts: boolean;

  // Actions
  fetchInitialData: () => Promise<void>;
  fetchHealth: () => Promise<void>;
  fetchStats: () => Promise<void>;
  fetchAlerts: () => Promise<void>;
  prependAlert: (alert: Alert) => void;
  selectAlert: (id: string | null) => Promise<void>;
  closeAlertDetail: () => void;
  setConnectionStatus: (status: ConnectionStatus) => void;
  incrementScannedFlows: (count?: number) => void;
  
  // Test Action Overrides
  toggleSimulatedOffline: () => Promise<void>;
  toggleSimulatedNotReady: () => Promise<void>;
  toggleSimulatedEmptyAlerts: () => Promise<void>;
  triggerFakeError: (msg: string) => void;
}

export const useSpectraStore = create<SpectraState>((set, get) => ({
  health: null,
  stats: null,
  connectionStatus: 'disconnected',
  isSystemLoading: true,
  systemError: null,

  alerts: [],
  totalScannedFlows: 0,
  totalFlaggedThreats: 0,

  selectedAlertId: null,
  selectedAlertDetail: null,
  isDetailLoading: false,
  detailError: null,

  simulatedOffline: false,
  simulatedNotReady: false,
  simulatedEmptyAlerts: false,

  /**
   * DATA LIFECYCLE (per integration contract):
   * On load: fetch health -> fetch stats -> fetch alerts (history)
   */
  fetchInitialData: async () => {
    set({ isSystemLoading: true, systemError: null });
    try {
      // 1. Fetch Health
      const health = await dataProvider.getHealth();
      set({ health });

      // 2. Fetch Stats
      const stats = await dataProvider.getStats();
      set({ stats, totalScannedFlows: stats.events_received });

      // 3. Fetch Historical Alerts
      const alerts = await dataProvider.getAlerts();
      set({
        alerts,
        totalFlaggedThreats: alerts.length,
        isSystemLoading: false,
        systemError: null,
      });
    } catch (err: any) {
      set({
        systemError: err?.message || 'Failed to connect to backend service',
        isSystemLoading: false,
        health: null,
      });
    }
  },

  fetchHealth: async () => {
    try {
      const health = await dataProvider.getHealth();
      set({ health, systemError: null });
    } catch (err: any) {
      set({ health: null, systemError: err?.message || 'Backend offline' });
    }
  },

  fetchStats: async () => {
    try {
      const stats = await dataProvider.getStats();
      set({ stats });
    } catch (err) {
      console.warn('Failed to fetch live stats', err);
    }
  },

  fetchAlerts: async () => {
    try {
      const alerts = await dataProvider.getAlerts();
      set({ alerts, totalFlaggedThreats: alerts.length });
    } catch (err) {
      console.warn('Failed to fetch historical alerts', err);
    }
  },

  /**
   * Prepend new incoming alert from WebSocket stream with subtle entry animation
   */
  prependAlert: (newAlert: Alert) => {
    set((state) => {
      // Prevent duplicates if already present
      if (state.alerts.some((a) => a.id === newAlert.id)) {
        return state;
      }
      const updatedAlerts = [newAlert, ...state.alerts];
      return {
        alerts: updatedAlerts,
        totalFlaggedThreats: updatedAlerts.length,
        // Also update stats alert count dynamically
        stats: state.stats,
      };
    });
  },

  /**
   * Select alert and fetch details from GET /alerts/{id} through data layer
   */
  selectAlert: async (id: string | null) => {
    if (!id) {
      set({ selectedAlertId: null, selectedAlertDetail: null, detailError: null });
      return;
    }

    set({ selectedAlertId: id, isDetailLoading: true, detailError: null });

    try {
      const detail = await dataProvider.getAlertById(id);
      if (!detail) {
        set({
          selectedAlertDetail: null,
          isDetailLoading: false,
          detailError: `Alert "${id}" not found (404).`,
        });
      } else {
        set({
          selectedAlertDetail: detail,
          isDetailLoading: false,
          detailError: null,
        });
      }
    } catch (err: any) {
      set({
        selectedAlertDetail: null,
        isDetailLoading: false,
        detailError: err?.message || 'Error fetching alert details',
      });
    }
  },

  closeAlertDetail: () => {
    set({ selectedAlertId: null, selectedAlertDetail: null, detailError: null });
  },

  setConnectionStatus: (status: ConnectionStatus) => {
    set({ connectionStatus: status });
  },

  incrementScannedFlows: (count = 1) => {
    set((state) => ({ totalScannedFlows: state.totalScannedFlows + count }));
  },

  // Interactive Test Overrides
  toggleSimulatedOffline: async () => {
    const current = getSimulatedOffline();
    setSimulatedOffline(!current);
    set({ simulatedOffline: !current });
    await get().fetchInitialData();
  },

  toggleSimulatedNotReady: async () => {
    const current = getSimulatedNotReady();
    setSimulatedNotReady(!current);
    set({ simulatedNotReady: !current });
    await get().fetchHealth();
  },

  toggleSimulatedEmptyAlerts: async () => {
    const current = getSimulatedEmptyAlerts();
    setSimulatedEmptyAlerts(!current);
    set({ simulatedEmptyAlerts: !current });
    await get().fetchAlerts();
  },

  triggerFakeError: (msg: string) => {
    set({ systemError: msg });
  },
}));
