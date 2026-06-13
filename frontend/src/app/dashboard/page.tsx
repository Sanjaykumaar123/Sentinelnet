"use client";

import { useState, useEffect } from "react";
import { Activity, Shield, AlertTriangle, Map as MapIcon, Terminal, Brain, Cpu, Zap, TrendingUp, Lock, BarChart2, Eye } from "lucide-react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { motion } from "framer-motion";
import clsx from "clsx";

interface AIModel {
    version: string;
    inference_mode: string;
    ai_pipeline: boolean;
    zero_shot_pipeline: boolean;
    avg_confidence: number;
}

interface Incidents24h {
    total_messages: number;
    blocked: number;
    opsec: number;
    phishing: number;
    ai_content: number;
    context_leakage: number;
    false_positive_rate: number;
}

interface DashboardStats {
    system_status: string;
    active_nodes: number;
    defcon: number;
    active_threats: number;
    trend_data: { time: string; value: number; opsec: number; phishing: number; ai_content: number }[];
    alerts: {
        id: string;
        title: string;
        risk: string;
        time: string;
        details: string;
        severity: string;
        confidence: number;
        model: string;
        reasons: string[];
    }[];
    logs: { time: string; type: string; message: string }[];
    geo_risks: { lat: number; lng: number; risk: string }[];
    ai_model?: AIModel;
    incidents_24h?: Incidents24h;
}

const StatCard = ({ icon: Icon, label, value, sub, color }: any) => (
    <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={clsx(
            "bg-slate-900/60 border rounded-xl p-5 backdrop-blur-sm relative overflow-hidden group hover:scale-[1.02] transition-transform duration-300",
            color === "red" ? "border-red-500/30 shadow-red-900/20 shadow-lg" :
            color === "yellow" ? "border-yellow-500/30" :
            color === "purple" ? "border-purple-500/30" :
            color === "teal" ? "border-teal-500/30" :
            "border-slate-700"
        )}
    >
        <div className={clsx(
            "absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-10 -translate-y-1/2 translate-x-1/2",
            color === "red" ? "bg-red-500" :
            color === "yellow" ? "bg-yellow-500" :
            color === "purple" ? "bg-purple-500" :
            color === "teal" ? "bg-teal-500" : "bg-slate-500"
        )} />
        <div className={clsx(
            "w-10 h-10 rounded-lg flex items-center justify-center mb-3",
            color === "red" ? "bg-red-500/10" :
            color === "yellow" ? "bg-yellow-500/10" :
            color === "purple" ? "bg-purple-500/10" :
            color === "teal" ? "bg-teal-500/10" : "bg-slate-700"
        )}>
            <Icon className={clsx(
                "w-5 h-5",
                color === "red" ? "text-red-400" :
                color === "yellow" ? "text-yellow-400" :
                color === "purple" ? "text-purple-400" :
                color === "teal" ? "text-teal-400" : "text-slate-400"
            )} />
        </div>
        <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</div>
        <div className={clsx(
            "text-2xl font-black",
            color === "red" ? "text-red-400" :
            color === "yellow" ? "text-yellow-400" :
            color === "purple" ? "text-purple-400" :
            color === "teal" ? "text-teal-400" : "text-white"
        )}>{value}</div>
        {sub && <div className="text-[10px] text-slate-500 mt-1 font-mono">{sub}</div>}
    </motion.div>
);

export default function Dashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null);

    const fetchStats = async () => {
        try {
            const token = localStorage.getItem("token");
            const headers: any = {};
            if (token) headers["Authorization"] = `Bearer ${token}`;
            const res = await fetch("/api/v1/dashboard/stats", { headers });
            if (res.ok) {
                const data = await res.json();
                setStats(data);
            }
        } catch (e) {
            console.error("Dashboard poll failed", e);
        }
    };

    useEffect(() => {
        fetchStats();
        const interval = setInterval(fetchStats, 5000);
        return () => clearInterval(interval);
    }, []);

    if (!stats) return (
        <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-teal-500 font-mono gap-4">
            <div className="w-16 h-16 border-4 border-teal-500/30 border-t-teal-500 rounded-full animate-spin" />
            <div className="animate-pulse text-sm">ESTABLISHING SECURE UPLINK...</div>
        </div>
    );

    const inc = stats.incidents_24h;
    const aiModel = stats.ai_model;

    return (
        <main className="min-h-screen bg-slate-950 p-6 font-mono text-slate-300 relative overflow-hidden">
            <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-5 pointer-events-none" />

            {/* Header */}
            <header className="flex justify-between items-end border-b border-slate-800 pb-6 mb-8 relative z-10">
                <div>
                    <div className="flex items-center gap-2 text-teal-500 mb-1">
                        <Shield className="w-5 h-5" />
                        <span className="tracking-widest text-xs">HQ COMMAND CENTER</span>
                    </div>
                    <h1 className="text-4xl font-black text-white tracking-tighter">SENTINEL NET</h1>
                    <div className="text-xs text-slate-500 mt-1">AI-Powered Threat Intelligence Platform v2.0</div>
                </div>
                <div className="flex gap-8 text-xs">
                    <div className="text-right">
                        <div className="text-slate-500">SYSTEM STATUS</div>
                        <div className={clsx(
                            "font-bold flex items-center justify-end gap-2",
                            stats.system_status === "OPERATIONAL" ? "text-emerald-400" : "text-rose-400"
                        )}>
                            {stats.system_status}
                            <span className={clsx(
                                "w-2 h-2 rounded-full animate-pulse",
                                stats.system_status === "OPERATIONAL" ? "bg-emerald-500" : "bg-rose-500"
                            )} />
                        </div>
                    </div>
                    <div className="text-right">
                        <div className="text-slate-500">AI ENGINE</div>
                        <div className={clsx(
                            "font-bold",
                            aiModel?.inference_mode === 'transformer' ? "text-purple-400" : "text-yellow-400"
                        )}>
                            {aiModel?.inference_mode?.toUpperCase() || 'LOADING'}
                        </div>
                    </div>
                    <div className="text-right">
                        <div className="text-slate-500">DEFCON</div>
                        <div className={clsx(
                            "font-bold text-xl",
                            stats.defcon <= 2 ? "text-red-500 animate-pulse" :
                                stats.defcon === 3 ? "text-orange-400" : "text-yellow-400"
                        )}>LEVEL {stats.defcon}</div>
                    </div>
                </div>
            </header>

            {/* AI Model Status Banner */}
            {aiModel && (
                <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={clsx(
                        "mb-6 p-4 rounded-xl border flex items-center justify-between relative overflow-hidden",
                        aiModel.inference_mode === 'transformer'
                            ? "bg-purple-950/30 border-purple-500/30"
                            : "bg-yellow-950/30 border-yellow-500/30"
                    )}
                >
                    <div className="flex items-center gap-3">
                        {aiModel.inference_mode === 'transformer'
                            ? <Zap className="w-5 h-5 text-purple-400" />
                            : <Cpu className="w-5 h-5 text-yellow-400" />
                        }
                        <div>
                            <div className={clsx(
                                "text-sm font-bold",
                                aiModel.inference_mode === 'transformer' ? "text-purple-400" : "text-yellow-400"
                            )}>
                                {aiModel.inference_mode === 'transformer'
                                    ? "⚡ TRANSFORMER AI ACTIVE"
                                    : "⚙ ENHANCED HEURISTICS MODE"
                                }
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                                Model: {aiModel.version} | Avg Confidence: {aiModel.avg_confidence}%
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center gap-6 text-[10px]">
                        <div className="text-center">
                            <div className={aiModel.ai_pipeline ? "text-emerald-400" : "text-slate-600"}>
                                {aiModel.ai_pipeline ? "● ACTIVE" : "○ OFFLINE"}
                            </div>
                            <div className="text-slate-500">AI Detector</div>
                        </div>
                        <div className="text-center">
                            <div className={aiModel.zero_shot_pipeline ? "text-emerald-400" : "text-slate-600"}>
                                {aiModel.zero_shot_pipeline ? "● ACTIVE" : "○ OFFLINE"}
                            </div>
                            <div className="text-slate-500">Zero-Shot NLI</div>
                        </div>
                        <div className="text-center">
                            <div className="text-emerald-400">● ACTIVE</div>
                            <div className="text-slate-500">Context Tracker</div>
                        </div>
                        <div className="text-center">
                            <div className="text-emerald-400">● ACTIVE</div>
                            <div className="text-slate-500">AES-256-GCM</div>
                        </div>
                    </div>
                </motion.div>
            )}

            {/* Incident Stats Row */}
            {inc && (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6 relative z-10">
                    <StatCard icon={AlertTriangle} label="OPSEC Incidents" value={inc.opsec} color="red" sub="24h" />
                    <StatCard icon={Eye} label="Phishing Detected" value={inc.phishing} color="yellow" sub="24h" />
                    <StatCard icon={Brain} label="AI Content" value={inc.ai_content} color="purple" sub="24h" />
                    <StatCard icon={Activity} label="Context Leakage" value={inc.context_leakage} color="red" sub="cross-msg" />
                    <StatCard icon={Shield} label="Messages Blocked" value={inc.blocked} color="red" sub={`of ${inc.total_messages}`} />
                    <StatCard icon={TrendingUp} label="False Positive %" value={`${inc.false_positive_rate}%`} color="teal" sub="estimated" />
                    <StatCard icon={Lock} label="Avg Confidence" value={`${aiModel?.avg_confidence || 0}%`} color="purple" sub="model output" />
                </div>
            )}

            {/* Main Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 relative z-10">
                {/* Charts + Alerts */}
                <div className="lg:col-span-3 space-y-6">
                    {/* Multi-series Threat Chart */}
                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm hover:border-teal-500/20 transition-colors">
                        <h2 className="text-sm font-bold text-white mb-6 flex items-center gap-2">
                            <BarChart2 className="w-4 h-4 text-teal-400" />
                            Threat Intelligence Feed — Live (5m buckets)
                        </h2>
                        <div className="h-[280px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={stats.trend_data}>
                                    <defs>
                                        <linearGradient id="colorOpsec" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                                            <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="colorPhish" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#eab308" stopOpacity={0.4} />
                                            <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="colorAI" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#a855f7" stopOpacity={0.4} />
                                            <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                                    <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                                    <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#fff', fontSize: 11 }}
                                    />
                                    <Legend wrapperStyle={{ fontSize: 10, color: '#64748b' }} />
                                    <Area type="monotone" dataKey="opsec" stroke="#f43f5e" strokeWidth={2} fill="url(#colorOpsec)" name="OPSEC" />
                                    <Area type="monotone" dataKey="phishing" stroke="#eab308" strokeWidth={2} fill="url(#colorPhish)" name="Phishing" />
                                    <Area type="monotone" dataKey="ai_content" stroke="#a855f7" strokeWidth={2} fill="url(#colorAI)" name="AI Content" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Alerts + Map */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Active Alerts */}
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm">
                            <h3 className="text-sm font-bold text-slate-400 mb-4 flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4 text-yellow-500" /> ACTIVE ALERTS
                            </h3>
                            <div className="space-y-3 max-h-[300px] overflow-y-auto">
                                {stats.alerts.length === 0 && (
                                    <div className="text-emerald-500/50 text-sm">No Active Threats Detected.</div>
                                )}
                                {stats.alerts.map((alert, i) => (
                                    <motion.div
                                        key={alert.id + i}
                                        initial={{ opacity: 0, x: -10 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        className="flex items-start gap-3 p-3 bg-red-500/5 border border-red-500/20 rounded hover:bg-red-500/10 cursor-pointer transition"
                                    >
                                        <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-white text-xs font-bold">{alert.title}</div>
                                            <div className="text-[10px] text-red-300/60 truncate">{alert.details}</div>
                                            {alert.reasons && alert.reasons[0] && (
                                                <div className="text-[10px] text-orange-400/70 mt-1 truncate">{alert.reasons[0]}</div>
                                            )}
                                            <div className="flex items-center gap-2 mt-1">
                                                <span className="text-[9px] text-slate-500">{new Date(alert.time).toLocaleTimeString()}</span>
                                                {alert.confidence > 0 && (
                                                    <span className="text-[9px] text-purple-400 font-mono">{alert.confidence}% conf</span>
                                                )}
                                                {alert.model && alert.model !== 'heuristic' && (
                                                    <span className="text-[9px] text-emerald-400 font-mono truncate max-w-[100px]">{alert.model}</span>
                                                )}
                                            </div>
                                        </div>
                                        <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded font-bold shrink-0">HIGH</span>
                                    </motion.div>
                                ))}
                            </div>
                        </div>

                        {/* Geo Map */}
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm">
                            <h3 className="text-sm font-bold text-slate-400 mb-4 flex items-center gap-2">
                                <MapIcon className="w-4 h-4 text-blue-500" /> GEOLOCATION RISK MAP
                            </h3>
                            <div className="h-[260px] w-full bg-slate-800/50 rounded flex items-center justify-center relative overflow-hidden">
                                <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-20" />
                                <div className="relative w-full h-full">
                                    {stats.geo_risks.map((pt, i) => (
                                        <div
                                            key={i}
                                            className="absolute"
                                            style={{
                                                top: `${((pt.lat % 7) + 3) * 10}%`,
                                                left: `${((pt.lng % 7) + 3) * 10}%`,
                                            }}
                                        >
                                            <div className="w-3 h-3 bg-red-500 rounded-full shadow-[0_0_15px_#ef4444] animate-ping absolute" />
                                            <div className="w-3 h-3 bg-red-500 rounded-full" />
                                        </div>
                                    ))}
                                    {stats.geo_risks.length === 0 && (
                                        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-xs text-emerald-500">
                                            GLOBAL THREAT LEVEL: MINIMAL
                                        </div>
                                    )}
                                </div>
                                <div className="absolute bottom-2 right-2 text-[10px] text-slate-500">LIVE SATELLITE FEED // SIMULATED</div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Sidebar: System Logs */}
                <div className="space-y-6">
                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm">
                        <h3 className="text-sm font-bold text-slate-400 mb-4 flex items-center gap-2">
                            <Terminal className="w-4 h-4 text-emerald-500" /> SYSTEM LOGS
                        </h3>
                        <div className="h-[500px] overflow-y-auto relative text-xs font-mono space-y-2 opacity-80 pr-2">
                            {stats.logs.map((log, i) => (
                                <div key={i} className="flex gap-2 text-slate-500 animate-in fade-in slide-in-from-right-2 duration-300">
                                    <span className="text-slate-700 whitespace-nowrap">{log.time}</span>
                                    <span className={clsx(
                                        "break-all",
                                        log.type.includes("THREAT") || log.type.includes("WARN") ? "text-red-400" :
                                        log.type.includes("PHISH") ? "text-yellow-400" :
                                        log.type.includes("AI") ? "text-purple-400" :
                                        log.type.includes("SYS") ? "text-slate-400" : "text-teal-500"
                                    )}>
                                        {log.type} {log.message}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </main>
    );
}
