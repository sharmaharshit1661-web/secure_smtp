import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Tooltip, ResponsiveContainer, Cell,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ReferenceLine, LabelList,
  RadialBarChart, RadialBar, PolarAngleAxis
} from 'recharts';
import Icon from '../components/Icon';
import HostRow from '../components/HostRow';
import { getHosts, getSessions, getComplianceSummary } from '../api/client';
import { getBarColor } from '../utils/colors';

const TOOLTIP_STYLE = {
  backgroundColor: '#0D0D0E',
  border: '1px solid #1F1F23',
  borderRadius: '8px',
  color: '#E8E8EC',
  fontSize: '12px',
  boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6)',
  padding: '10px 14px',
};

const CustomBarTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const color = data.color || data.fill || '#10B981';
    return (
      <div style={TOOLTIP_STYLE}>
        <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: 4, color: '#E8E8EC' }}>
          {data.ip || data.name}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: color,
              boxShadow: `0 0 6px ${color}`,
            }}
          />
          <span style={{ color: '#A1A1AA', fontSize: 11 }}>Risk Score:</span>
          <span style={{ fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>
            {data.score} / 100
          </span>
          <span
            className="badge"
            style={{
              fontSize: 9,
              padding: '1px 5px',
              backgroundColor: `${color}18`,
              color,
              borderColor: `${color}40`,
            }}
          >
            {data.tier}
          </span>
        </div>
        <div style={{ fontSize: 11, color: '#71717A' }}>
          {data.sessions} {data.sessions === 1 ? 'flow' : 'flows'} · Click to inspect host
        </div>
      </div>
    );
  }
  return null;
};

export default function FleetOverview() {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [compliance, setCompliance] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('ALL');
  const [graphView, setGraphView] = useState('bars');

  const fetchTelemetry = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      const [hostsRes, sessionsRes, complianceRes] = await Promise.allSettled([
        getHosts(),
        getSessions(200),
        getComplianceSummary(),
      ]);

      if (hostsRes.status === 'fulfilled' && hostsRes.value) {
        const sorted = (hostsRes.value || []).sort(
          (a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0)
        );
        setHosts(sorted);
      }

      if (sessionsRes.status === 'fulfilled' && sessionsRes.value) {
        setSessions(sessionsRes.value || []);
      }

      if (complianceRes.status === 'fulfilled' && complianceRes.value) {
        setCompliance(complianceRes.value);
      }
    } catch (err) {
      console.error('Failed to fetch fleet telemetry:', err);
      setError(err.message || 'Unable to connect to backend API');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  // ── Metrics & Summaries ───────────────────────────────────────────────────
  const totalHosts = hosts.length;
  const totalSessions = hosts.reduce((sum, h) => sum + (h.session_count || 0), 0) || sessions.length;
  const avgRisk = totalHosts > 0
    ? hosts.reduce((sum, h) => sum + (h.aggregate_risk_score || 0), 0) / totalHosts
    : 0;

  const criticalHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) >= 75).length;
  const highHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) >= 50 && (h.aggregate_risk_score || 0) < 75).length;
  const cleanHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) < 25).length;

  // Encryption Ratio
  const encryptedCount = useMemo(() => {
    return sessions.filter((s) => {
      const mode = (s.tls_mode || '').toLowerCase();
      const findings = s.findings || [];
      const isStripped = findings.some((f) => f.rule_id === 'starttls-stripped' || f.rule_id === 'no-tls');
      return (mode === 'starttls' || mode === 'tls') && !isStripped;
    }).length;
  }, [sessions]);

  const encryptionRate = totalSessions > 0
    ? Math.round((encryptedCount / totalSessions) * 100)
    : cleanHosts > 0 && totalHosts > 0
      ? Math.round((cleanHosts / totalHosts) * 100)
      : 0;

  // ── Chart Data ────────────────────────────────────────────────────────────
  const chartData = useMemo(() => {
    return hosts.map((h) => {
      const score = Math.round(h.aggregate_risk_score || 0);
      const color = getBarColor(score);
      const tier = score >= 75 ? 'Critical' : score >= 50 ? 'High' : score >= 25 ? 'Medium' : 'Clean';
      return {
        ip: h.ip,
        score,
        sessions: h.session_count || 0,
        hostId: h.host_id,
        color,
        tier,
      };
    });
  }, [hosts]);

  const radialChartData = useMemo(() => {
    return chartData.map((h) => ({
      name: h.ip,
      score: h.score,
      fill: h.color,
      hostId: h.hostId,
      tier: h.tier,
      sessions: h.sessions,
    }));
  }, [chartData]);

  // ── Protocol Conformance Breakdown ────────────────────────────────────────
  const protocolBreakdown = useMemo(() => {
    let modernTls = 0;
    let opportunistic = 0;
    let unencrypted = 0;

    if (sessions.length > 0) {
      sessions.forEach((s) => {
        const mode = (s.tls_mode || '').toLowerCase();
        const findings = s.findings || [];
        const isDowngrade = findings.some((f) => f.rule_id === 'starttls-stripped' || f.rule_id === 'no-tls');
        const isModern = s.tls_version === 'TLSv1.3' || (s.risk_score || 0) < 15;

        if (isDowngrade || mode === 'none') unencrypted += 1;
        else if (isModern) modernTls += 1;
        else opportunistic += 1;
      });
    } else {
      modernTls = cleanHosts * 2;
      opportunistic = (totalHosts - cleanHosts - criticalHosts) * 2;
      unencrypted = criticalHosts * 2;
    }

    const total = (modernTls + opportunistic + unencrypted) || 1;

    return [
      {
        name: 'TLS 1.3 Modern',
        label: 'TLS 1.3 Modern',
        value: modernTls,
        count: modernTls,
        percentage: Math.round((modernTls / total) * 100),
        color: '#10B981',
      },
      {
        name: 'Opportunistic STARTTLS',
        label: 'Opportunistic STARTTLS',
        value: opportunistic,
        count: opportunistic,
        percentage: Math.round((opportunistic / total) * 100),
        color: '#F59E0B',
      },
      {
        name: 'Unencrypted / Downgraded',
        label: 'Unencrypted / Downgraded',
        value: unencrypted,
        count: unencrypted,
        percentage: Math.round((unencrypted / total) * 100),
        color: '#EF4444',
      },
    ];
  }, [sessions, cleanHosts, criticalHosts, totalHosts]);

  const pieChartData = useMemo(() => {
    const active = protocolBreakdown.filter((item) => item.value > 0);
    return active.length > 0
      ? active
      : [{ name: 'No Traffic', value: 1, color: '#27272A', percentage: 0 }];
  }, [protocolBreakdown]);

  // ── Filtered Hosts ────────────────────────────────────────────────────────
  const filteredHosts = useMemo(() => {
    return hosts.filter((h) => {
      const matchesSearch = !search || h.ip.toLowerCase().includes(search.toLowerCase());
      const score = h.aggregate_risk_score || 0;
      if (!matchesSearch) return false;
      if (tierFilter === 'CRITICAL') return score >= 75;
      if (tierFilter === 'HIGH') return score >= 50 && score < 75;
      if (tierFilter === 'MEDIUM') return score >= 25 && score < 50;
      if (tierFilter === 'CLEAN') return score < 25;
      return true;
    });
  }, [hosts, search, tierFilter]);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      {/* ── CLEAN PAGE HEADER ───────────────────────────────────────────────── */}
      <div className="flex justify-between items-start flex-wrap gap-4 pb-2 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-xl font-bold tracking-tight" style={{ color: '#E8E8EC' }}>
              Fleet Overview
            </h1>
            <span className="live-surveillance-chip">
              <span className="live-surveillance-dot" />
              <span>Live Surveillance</span>
            </span>
          </div>
          <p className="text-secondary text-sm">
            Passive cryptographic posture and security monitoring across all monitored mail servers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            className="btn btn-outline"
            onClick={() => fetchTelemetry(true)}
            disabled={refreshing}
          >
            <Icon name="activity" size={15} />
            {refreshing ? 'Refreshing…' : 'Sync'}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => navigate('/ingest')}
          >
            <Icon name="bolt" size={15} />
            Ingest PCAP
          </button>
        </div>
      </div>

      {/* ── KEY METRICS (4 Clean Cards) ─────────────────────────────────────── */}
      <div className="grid grid-4 gap-4">
        <div className="card p-5">
          <div className="text-secondary text-xs font-medium uppercase tracking-wider mb-2">
            Audited Hosts
          </div>
          <div className="text-2xl font-bold" style={{ color: '#E8E8EC', fontFamily: 'var(--font-mono)' }}>
            {loading ? '…' : totalHosts}
          </div>
          <div className="text-secondary text-xs mt-1">
            Monitored IP subnets
          </div>
        </div>

        <div className="card p-5">
          <div className="text-secondary text-xs font-medium uppercase tracking-wider mb-2">
            Analyzed Sessions
          </div>
          <div className="text-2xl font-bold" style={{ color: '#E8E8EC', fontFamily: 'var(--font-mono)' }}>
            {loading ? '…' : totalSessions}
          </div>
          <div className="text-secondary text-xs mt-1">
            SMTP, IMAP, and POP3 flows
          </div>
        </div>

        <div className="card p-5">
          <div className="text-secondary text-xs font-medium uppercase tracking-wider mb-2">
            Average Risk Score
          </div>
          <div className="flex items-baseline gap-2">
            <span
              className="text-2xl font-bold"
              style={{
                fontFamily: 'var(--font-mono)',
                color: avgRisk >= 50 ? 'var(--sev-critical)' : avgRisk >= 25 ? 'var(--sev-medium)' : 'var(--accent, #10B981)',
              }}
            >
              {loading ? '…' : avgRisk.toFixed(1)}
            </span>
            <span className="text-secondary text-xs">/ 100</span>
          </div>
          <div className="text-secondary text-xs mt-1">
            {criticalHosts > 0 || highHosts > 0
              ? `${criticalHosts + highHosts} hosts elevated or critical`
              : 'Fleet posture is healthy'}
          </div>
        </div>

        <div className="card p-5">
          <div className="text-secondary text-xs font-medium uppercase tracking-wider mb-2">
            Encryption Ratio
          </div>
          <div
            className="text-2xl font-bold"
            style={{
              fontFamily: 'var(--font-mono)',
              color: encryptionRate >= 80 ? 'var(--accent, #10B981)' : 'var(--sev-high)',
            }}
          >
            {loading ? '…' : `${encryptionRate}%`}
          </div>
          <div className="text-secondary text-xs mt-1">
            {encryptedCount} of {totalSessions} flows encrypted
          </div>
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div
          className="card p-4"
          style={{
            borderColor: 'var(--sev-critical)',
            backgroundColor: 'rgba(239, 68, 68, 0.08)',
          }}
        >
          <div className="flex justify-between items-center">
            <div className="text-xs" style={{ color: 'var(--sev-critical)' }}>
              <strong>API Notice:</strong> {error} — Ensure FastAPI backend is running.
            </div>
            <button className="btn btn-xs btn-outline" onClick={() => fetchTelemetry(true)}>
              Retry
            </button>
          </div>
        </div>
      )}

      {/* ── TWO CLEAN VISUAL PANELS ─────────────────────────────────────────── */}
      <div className="grid grid-2 gap-4">
        {/* Panel 1: Host Risk Distribution Graph */}
        <div className="card p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-1">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: '#E8E8EC' }}>
                  Host Risk Distribution
                </h2>
                <p className="text-secondary text-xs">
                  Cryptographic risk attribution per host. Click any item to inspect sessions.
                </p>
              </div>

              {/* Graph View Mode Toggle */}
              <div
                className="flex items-center rounded"
                style={{ background: '#121214', border: '1px solid #27272A', padding: '2px' }}
              >
                <button
                  type="button"
                  onClick={() => setGraphView('bars')}
                  className="transition-all"
                  style={{
                    backgroundColor: graphView === 'bars' ? '#10B981' : 'transparent',
                    color: graphView === 'bars' ? '#050505' : '#A1A1AA',
                    fontWeight: graphView === 'bars' ? 700 : 500,
                    fontSize: '11px',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    border: 'none',
                    cursor: 'pointer',
                    boxShadow: graphView === 'bars' ? '0 1px 6px rgba(16, 185, 129, 0.3)' : 'none',
                  }}
                  title="Horizontal Bar Graph with Threshold Reference Bands"
                >
                  Bars
                </button>
                <button
                  type="button"
                  onClick={() => setGraphView('radial')}
                  className="transition-all"
                  style={{
                    backgroundColor: graphView === 'radial' ? '#10B981' : 'transparent',
                    color: graphView === 'radial' ? '#050505' : '#A1A1AA',
                    fontWeight: graphView === 'radial' ? 700 : 500,
                    fontSize: '11px',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    border: 'none',
                    cursor: 'pointer',
                    boxShadow: graphView === 'radial' ? '0 1px 6px rgba(16, 185, 129, 0.3)' : 'none',
                  }}
                  title="Concentric Radar Arc Graph"
                >
                  Radar
                </button>
              </div>
            </div>

            <div className="my-1" style={{ height: 215, position: 'relative' }}>
              {chartData.length > 0 ? (
                graphView === 'bars' ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={chartData}
                      margin={{ top: 12, right: 35, left: 10, bottom: 0 }}
                      barCategoryGap="20%"
                    >
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#1F1F23" />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        ticks={[0, 25, 50, 75, 100]}
                        stroke="#52525B"
                        fontSize={10}
                        tickLine={false}
                        axisLine={{ stroke: '#1F1F23' }}
                        unit="%"
                      />
                      <YAxis
                        type="category"
                        dataKey="ip"
                        stroke="#E8E8EC"
                        fontSize={11}
                        fontFamily="var(--font-mono)"
                        tickLine={false}
                        axisLine={false}
                        width={100}
                      />
                      <Tooltip content={<CustomBarTooltip />} cursor={{ fill: 'rgba(255, 255, 255, 0.03)' }} />
                      <ReferenceLine x={25} stroke="rgba(16, 185, 129, 0.3)" strokeDasharray="3 3" />
                      <ReferenceLine x={50} stroke="rgba(245, 158, 11, 0.3)" strokeDasharray="3 3" />
                      <ReferenceLine x={75} stroke="rgba(239, 68, 68, 0.3)" strokeDasharray="3 3" />
                      <Bar
                        dataKey="score"
                        radius={[0, 4, 4, 0]}
                        barSize={16}
                        background={{ fill: '#141416', radius: [0, 4, 4, 0] }}
                        onClick={(data) => {
                          if (data && data.hostId) navigate(`/sessions/${data.hostId}`);
                        }}
                        cursor="pointer"
                      >
                        <LabelList
                          dataKey="score"
                          position="right"
                          fill="#E8E8EC"
                          fontSize={11}
                          fontFamily="var(--font-mono)"
                          offset={8}
                          formatter={(v) => `${v}`}
                        />
                        {chartData.map((entry) => (
                          <Cell key={`bar-${entry.hostId}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center gap-4 h-full">
                    <div style={{ width: '45%', height: '100%', position: 'relative' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <RadialBarChart
                          cx="50%"
                          cy="50%"
                          innerRadius="28%"
                          outerRadius="95%"
                          barSize={10}
                          data={radialChartData}
                          startAngle={90}
                          endAngle={-270}
                        >
                          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                          <RadialBar
                            background={{ fill: '#161619' }}
                            dataKey="score"
                            cornerRadius={5}
                          >
                            {radialChartData.map((entry) => (
                              <Cell key={`radial-${entry.hostId}`} fill={entry.fill} />
                            ))}
                          </RadialBar>
                          <Tooltip content={<CustomBarTooltip />} />
                        </RadialBarChart>
                      </ResponsiveContainer>
                      <div
                        style={{
                          position: 'absolute',
                          top: '50%',
                          left: '50%',
                          transform: 'translate(-50%, -50%)',
                          textAlign: 'center',
                          pointerEvents: 'none',
                        }}
                      >
                        <div className="text-base font-bold font-mono" style={{ color: '#E8E8EC', lineHeight: 1 }}>
                          {Math.round(Math.max(...chartData.map((d) => d.score), 0))}
                        </div>
                        <div className="text-secondary" style={{ fontSize: '9px', textTransform: 'uppercase', marginTop: '2px' }}>
                          Peak
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col justify-center gap-2 flex-1 pr-2">
                      {chartData.map((h) => (
                        <div
                          key={h.hostId}
                          onClick={() => navigate(`/sessions/${h.hostId}`)}
                          className="flex items-center justify-between p-2 rounded cursor-pointer transition-all"
                          style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid #1F1F23' }}
                          onMouseEnter={(e) => { e.currentTarget.style.borderColor = h.color; }}
                          onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#1F1F23'; }}
                        >
                          <div className="flex items-center gap-2">
                            <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: h.color, boxShadow: `0 0 6px ${h.color}` }} />
                            <span className="font-mono text-xs font-bold" style={{ color: '#E8E8EC' }}>{h.ip}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="badge" style={{ fontSize: '9px', padding: '1px 5px', color: h.color, borderColor: `${h.color}40` }}>
                              {h.tier}
                            </span>
                            <span className="font-mono text-xs font-bold" style={{ color: h.color }}>{h.score}/100</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              ) : (
                <div className="h-full flex items-center justify-center text-secondary text-xs">
                  No host telemetry available.
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between text-xs text-secondary pt-3 border-t mt-3" style={{ borderColor: 'var(--border-subtle)' }}>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--sev-clean)' }} /> Clean (&lt;25)
              </span>
              <span className="flex items-center gap-1">
                <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--sev-medium)' }} /> Medium (25–49)
              </span>
              <span className="flex items-center gap-1">
                <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--sev-critical)' }} /> Critical (≥75)
              </span>
            </div>
            <span>{totalHosts} Hosts</span>
          </div>
        </div>

        {/* Panel 2: Protocol & Security Conformance */}
        <div className="card p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-1">
              <h2 className="text-sm font-semibold" style={{ color: '#E8E8EC' }}>
                Transport Security Conformance
              </h2>
              <span className="text-secondary text-xs">
                {totalSessions} Flows
              </span>
            </div>
            <p className="text-secondary text-xs mb-4">
              Breakdown of negotiated mail encryption modes across monitored traffic.
            </p>

            {/* Pie / Donut Chart & Side Breakdown */}
            <div className="flex items-center gap-5 my-1" style={{ height: 215 }}>
              {/* Pie / Donut Visual */}
              <div style={{ width: '45%', height: '100%', position: 'relative' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieChartData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={78}
                      paddingAngle={pieChartData.length > 1 ? 3 : 0}
                      stroke="#0D0D0E"
                      strokeWidth={2}
                    >
                      {pieChartData.map((entry, index) => (
                        <Cell key={`pie-cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={TOOLTIP_STYLE}
                      formatter={(val, name, item) => [
                        `${val} flows (${item.payload.percentage}%)`,
                        name,
                      ]}
                    />
                  </PieChart>
                </ResponsiveContainer>

                {/* Donut Center Statistic */}
                <div
                  style={{
                    position: 'absolute',
                    top: '50%',
                    left: '50%',
                    transform: 'translate(-50%, -50%)',
                    textAlign: 'center',
                    pointerEvents: 'none',
                  }}
                >
                  <div
                    className="text-lg font-bold"
                    style={{ color: '#E8E8EC', fontFamily: 'var(--font-mono)', lineHeight: 1 }}
                  >
                    {totalSessions}
                  </div>
                  <div
                    className="text-secondary"
                    style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.04em', marginTop: '2px' }}
                  >
                    Flows
                  </div>
                </div>
              </div>

              {/* Side Legend with Flow Counts & Percentages */}
              <div className="flex flex-col justify-center gap-3 flex-1 pr-2">
                {protocolBreakdown.map((item) => (
                  <div key={item.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        style={{
                          width: '9px',
                          height: '9px',
                          borderRadius: '50%',
                          backgroundColor: item.color,
                          display: 'inline-block',
                          flexShrink: 0,
                        }}
                      />
                      <span className="text-xs" style={{ color: '#E8E8EC' }}>
                        {item.name}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-right" style={{ minWidth: '90px' }}>
                      <span className="font-bold" style={{ color: item.color }}>
                        {item.percentage}%
                      </span>
                      <span className="text-secondary ml-1" style={{ fontSize: '11px' }}>
                        ({item.value})
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-3 border-t mt-3 flex justify-between items-center text-xs text-secondary" style={{ borderColor: 'var(--border-subtle)' }}>
            <span>
              Standard: NIST SP 800-52r2 {compliance?.overall_status ? `(${compliance.overall_status})` : ''}
            </span>
            <button
              type="button"
              className="text-xs hover:underline"
              style={{ color: 'var(--accent, #10B981)', background: 'none', border: 'none', cursor: 'pointer' }}
              onClick={() => navigate('/rules')}
            >
              View Compliance Rules →
            </button>
          </div>
        </div>
      </div>

      {/* ── HOST INVENTORY TABLE ────────────────────────────────────────────── */}
      <div className="card p-5">
        <div className="flex justify-between items-center flex-wrap gap-3 mb-4">
          <div>
            <h2 className="text-sm font-semibold" style={{ color: '#E8E8EC' }}>
              Monitored Hosts ({filteredHosts.length})
            </h2>
            <p className="text-secondary text-xs">
              Select any host to inspect active sessions, cipher suites, and certificates.
            </p>
          </div>

          {/* Search & Filters */}
          <div className="flex gap-2 items-center flex-wrap">
            <div style={{ position: 'relative', width: '220px' }}>
              <input
                type="text"
                className="input text-xs"
                placeholder="Search IP address…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{
                  width: '100%',
                  fontFamily: 'var(--font-mono)',
                  padding: '6px 28px 6px 10px',
                  borderRadius: '6px',
                }}
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  style={{
                    position: 'absolute',
                    right: '8px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    color: 'var(--text-muted)',
                    fontSize: '11px',
                  }}
                >
                  ✕
                </button>
              )}
            </div>

            <div className="flex gap-1">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'CLEAN'].map((tier) => (
                <button
                  key={tier}
                  type="button"
                  className={`btn btn-xs ${tierFilter === tier ? 'btn-primary' : 'btn-outline'}`}
                  style={{ fontSize: '11px', padding: '5px 10px' }}
                  onClick={() => setTierFilter(tier)}
                >
                  {tier}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Rows */}
        {loading ? (
          <div className="flex flex-col gap-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="skeleton" style={{ height: '56px', width: '100%' }} />
            ))}
          </div>
        ) : filteredHosts.length > 0 ? (
          <div className="flex flex-col gap-2">
            {filteredHosts.map((host) => (
              <HostRow key={host.host_id} host={host} />
            ))}
          </div>
        ) : (
          <div className="empty-state py-8 text-center">
            <div className="text-secondary text-sm">
              {search || tierFilter !== 'ALL'
                ? 'No hosts match your active search or risk tier filters.'
                : 'No hosts currently monitored. Ingest a PCAP file to begin.'}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
