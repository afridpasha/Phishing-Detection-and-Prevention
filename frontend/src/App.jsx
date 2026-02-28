import React from 'react';
import ThreatStatsPanel from './components/ThreatStatsPanel';
import ModelPerformance from './components/ModelPerformance';
import ThreatMapView from './components/ThreatMapView';
import IOCExplorer from './components/IOCExplorer';
import LiveFeed from './components/LiveFeed';
import AlertsPanel from './components/AlertsPanel';

const layoutStyle = {
  fontFamily: 'system-ui, -apple-system, Segoe UI, sans-serif',
  padding: '20px',
  background: 'linear-gradient(145deg, #f4f7fb, #eef2ff)',
  minHeight: '100vh',
};

const gridStyle = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
  gap: '16px',
};

export default function App() {
  return (
    <div style={layoutStyle}>
      <h1>Phishing Shield 2.0 - Admin Dashboard</h1>
      <div style={gridStyle}>
        <ThreatStatsPanel />
        <ModelPerformance />
        <ThreatMapView />
        <IOCExplorer />
        <LiveFeed />
        <AlertsPanel />
      </div>
    </div>
  );
}
