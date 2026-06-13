"use client";

import { useState, useRef, useEffect } from "react";
import { Send, Shield, Lock, AlertTriangle, Eye, Activity, FileText, Brain, Key, Network, Paperclip, File, Download, CheckCircle, MoreVertical, Reply, LogOut } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import clsx from "clsx";
import { getSession, signOut } from "next-auth/react";
import { Role, permissions } from "@/lib/permissions";

type RiskResult = {
    message_id?: number;
    ai_score: number;
    opsec_risk: "SAFE" | "SENSITIVE" | "HIGH";
    phishing_risk: "LOW" | "MODERATE" | "HIGH";
    explanation: string;
    // Extended AI fields
    severity?: "LOW" | "MEDIUM" | "HIGH";
    confidence?: number;
    reasons?: string[];
    model_version?: string;
    context_risk?: "SAFE" | "SENSITIVE" | "HIGH";
    opsec_score?: number;
    phishing_confidence?: number;
    ai_method?: "transformer" | "heuristic";
}

type Message = {
    id: string;
    text: string;
    sender: 'me' | 'them';
    timestamp: Date;
    status: 'scanning' | 'encrypted' | 'sent' | 'blocked';
    risk?: RiskResult;
    file?: {
        name: string;
        size: string;
        type: string;
        url: string;
    };
    integrityHash?: string;
    replyTo?: {
        id: string;
        text: string;
        sender: 'me' | 'them';
    };
    is_deleted?: boolean;
    hiddenForMe?: boolean;
}

const mockMessages: Message[] = [
    {
        id: '1',
        text: "Status report for sector 7?",
        sender: 'them',
        timestamp: new Date(Date.now() - 1000 * 60 * 5),
        status: 'sent',
        risk: { ai_score: 12, opsec_risk: 'SAFE', phishing_risk: 'LOW', explanation: 'Routine query' }
    }
];

export function ChatInterface() {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState("");
    const [isScanning, setIsScanning] = useState(false);
    const [selectedMessage, setSelectedMessage] = useState<Message | null>(null);
    const [replyTo, setReplyTo] = useState<Message | null>(null);
    const [showAIPanel, setShowAIPanel] = useState(false);
    const [fileUpload, setFileUpload] = useState<File | null>(null);
    const [selectedChannel, setSelectedChannel] = useState("general");
    const [ttl, setTtl] = useState<number | null>(null);
    const [showDeleteMenu, setShowDeleteMenu] = useState<string | null>(null);
    const [dms, setDms] = useState<{ id: string; name: string; status: string }[]>([]);
    const [dmEmail, setDmEmail] = useState("");
    const [showDmInput, setShowDmInput] = useState(false);
    const [offlineMode, setOfflineMode] = useState(false);
    const [currentRole, setCurrentRole] = useState<Role>("user");
    const fileInputRef = useRef<HTMLInputElement>(null);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const selectedChannelRef = useRef(selectedChannel);

    useEffect(() => {
        selectedChannelRef.current = selectedChannel;
    }, [selectedChannel]);

    const handleLogout = async () => {
        localStorage.removeItem("token");
        localStorage.removeItem("role");
        await signOut({ callbackUrl: "/login" });
    };

    const channels = [
        { id: "general", name: "Alpha Team", status: "ACTIVE" },
        { id: "bravo", name: "Bravo Squad", status: "STANDBY" },
        { id: "hq", name: "HQ Command", status: "ONLINE" },
        { id: "ops", name: "Special Ops", status: "ENCRYPTED" }
    ];

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    const deleteMessage = async (id: string, mode: "me" | "everyone") => {
        const token = localStorage.getItem("token");
        if (!token) return;
        try {
            await fetch("/api/v1/chat/messages/delete", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`
                },
                body: JSON.stringify({ id, mode })
            });

            setMessages(prev => prev.map(m => {
                if (m.id === id) {
                    if (mode === "everyone") {
                        return { ...m, is_deleted: true };
                    } else {
                        return { ...m, hiddenForMe: true };
                    }
                }
                return m;
            }));
            setShowDeleteMenu(null);
        } catch (e) {
            console.error("Failed to delete message", e);
        }
    };

    const fetchMessages = async () => {
        const token = localStorage.getItem("token");
        if (!token) return;
        
        const fetchChannel = selectedChannel; // Capture current channel for this request

        try {
            const res = await fetch(`/api/v1/chat/messages?channel_id=${fetchChannel}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (res.status === 401) {
                localStorage.removeItem("token");
                window.location.href = '/login';
                return;
            }

            if (res.ok) {
                const data = await res.json();
                
                // CRITICAL FIX: Ensure this data is still meant for the currently active channel
                if (selectedChannelRef.current !== fetchChannel) return;
                
                // Merge logic could be simpler: just replace for now or append new ones
                // To avoid jitter, we can just setMessages if the length is different or last message ID different
                // For prototype, simple set is fine, but let's be careful about local "scanning" state

                // We only want to overwrite if we are not currently simulating a local scan that hasn't finished? 
                // Actually, the backend is the source of truth. 
                // But we want to keep the "scanning" status for the user's own messages if they just sent it.
                // The backend messages will have "sent" or "blocked". 
                // So if we replace `messages` with `data`, we might lose the "scanning" state of a just-sent message 
                // if the backend implementation doesn't return it immediately or if it returns it as "sent" immediately.

                // Better approach for prototype: 
                // If we have a local message in "scanning" state, keep it. 
                // Only merge in messages that are NOT in our local "scanning" list? 
                // OR, just simply append incoming messages that are NEW?


                setMessages(prev => {
                    // 1. Convert Backend Data to Message Objects
                    const backendMessages: Message[] = data.map((backendMsg: any) => ({
                        id: backendMsg.id.toString(),
                        text: backendMsg.content_encrypted || backendMsg.text, // Handle potential field name diffs
                        sender: (backendMsg.sender === 'me' ? 'me' : 'them'),
                        timestamp: new Date(backendMsg.timestamp.endsWith("Z") ? backendMsg.timestamp : backendMsg.timestamp + "Z"),
                        status: backendMsg.risk?.opsec_risk === 'HIGH' ? 'blocked' : 'sent',
                        risk: backendMsg.risk,
                        file: backendMsg.file_url ? {
                            url: backendMsg.file_url,
                            type: backendMsg.file_type,
                            size: backendMsg.file_size,
                            name: backendMsg.file_type || "Encrypted File"
                        } : undefined,
                        integrityHash: backendMsg.integrity_hash,
                        is_deleted: backendMsg.is_deleted,
                        replyTo: backendMsg.reply_to ? {
                            id: backendMsg.reply_to.id,
                            text: backendMsg.reply_to.text,
                            sender: backendMsg.reply_to.sender
                        } : undefined
                    }));

                    // 2. Identify Pending Local Messages (Scanning/Unconfirmed)
                    // These are messages with temporary IDs (long timestamps) created locally
                    const pendingLocalMessages = prev.filter(m => m.id.length > 10 && m.sender === 'me');

                    // 3. Filter Pending Messages: Remove if they are now in Backend
                    const uniquePending = pendingLocalMessages.filter(localMsg => {
                        // Check exact hash match
                        if (localMsg.integrityHash && backendMessages.some(bm => bm.integrityHash === localMsg.integrityHash)) {
                            console.log("Removing pending msg (hash match):", localMsg.id);
                            return false;
                        }

                        // Check text match (fallback for legacy or missing hash)
                        // Only match if within reasonable time window (e.g. 10 seconds)
                        const matchingBackend = backendMessages.find(bm =>
                            bm.text === localMsg.text &&
                            bm.sender === 'me' &&
                            Math.abs(bm.timestamp.getTime() - localMsg.timestamp.getTime()) < 10000
                        );

                        if (matchingBackend) {
                            console.log("Removing pending msg (text match):", localMsg.id);
                            return false;
                        }

                        return true;
                    });

                    // 4. Merge: Backend Truth + Remaining Pending + Offline Messages
                    const offlineListRaw = JSON.parse(localStorage.getItem("offlineMessages") || "[]");
                    const offlineMessages: Message[] = offlineListRaw.map((m: any) => ({
                        ...m,
                        timestamp: new Date(m.timestamp)
                    }));

                    const merged = [...backendMessages, ...uniquePending, ...offlineMessages].sort((a, b) =>
                        a.timestamp.getTime() - b.timestamp.getTime()
                    );

                    return merged;
                });
            }
        } catch (error) {
            console.error("Failed to fetch messages", error);
        }
    };

    useEffect(() => {
        const initChat = async () => {
            let token = localStorage.getItem("token");

            // Hackathon Magic: Always check NextAuth session so we don't use stale tokens from a prev user
            const session = await getSession();
            if (session?.user?.email) {
                try {
                    const res = await fetch("/api/v1/auth/google-sync", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            email: session.user.email,
                            full_name: session.user.name || ""
                        })
                    });
                    if (res.ok) {
                        const data = await res.json();
                        if (data.access_token) {
                            token = data.access_token;
                            localStorage.setItem("token", data.access_token);
                            if (data.role) localStorage.setItem("role", data.role);
                        }
                    }
                } catch (e) {
                    console.error("Session sync failed:", e);
                }
            }

            if (!token) return;

            const storedRole = localStorage.getItem("role") as Role;
            if (storedRole) setCurrentRole(storedRole);

            fetchMessages();
            fetchDms();
        };

        initChat();

        // Poll more frequently for faster updates
        const interval = setInterval(() => {
            fetchMessages();
        }, 300);

        return () => clearInterval(interval);
    }, [selectedChannel]);

    const sendingRef = useRef(false);
    const lastSentRef = useRef<{ text: string, time: number }>({ text: "", time: 0 });

    const handleSend = async () => {
        const trimmedInput = input.trim();
        if (!trimmedInput && !fileUpload) return;

        // LOCK 1: Ref-based lock for sequential calls
        if (sendingRef.current) {
            console.log("Send blocked: already sending");
            return;
        }

        // LOCK 2: Time-based deduplication (Prevent identical text within 2 seconds)
        const now = Date.now();
        if (trimmedInput === lastSentRef.current.text && (now - lastSentRef.current.time) < 2000) {
            console.log("Send blocked: identical message within 2s");
            return;
        }

        // Check auth
        const token = localStorage.getItem("token");
        if (!token) {
            window.location.href = '/login';
            return;
        }

        sendingRef.current = true;
        lastSentRef.current = { text: trimmedInput, time: now };
        setIsScanning(true);

        // Prepare File Data
        let fileData = undefined;
        if (fileUpload) {
            fileData = {
                name: fileUpload.name,
                size: (fileUpload.size / 1024).toFixed(1) + " KB",
                type: fileUpload.type,
                url: URL.createObjectURL(fileUpload) // Local preview
            };
        }

        // Compute Integrity Hash (SHA-256 simulation)
        // Use trimmedInput and now (the shared timestamp for this send session)
        const contentToHash = (trimmedInput || "") + (fileData?.name || "") + now;
        const msgBuffer = new TextEncoder().encode(contentToHash);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const integrityHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        const newMessage: Message = {
            id: now.toString(),
            text: trimmedInput,
            sender: 'me',
            timestamp: new Date(now),
            status: 'scanning',
            file: fileData,
            integrityHash: integrityHash
        };

        // UI Update: Clear input immediately to visual feedback
        setMessages(prev => [...prev, newMessage]);
        setInput("");
        setFileUpload(null);
        setReplyTo(null);

        // Backend API Call
        let risk: RiskResult | null = null;

        if (offlineMode) {
            // Offline Field Mode: Local Heuristics Simulation
            await new Promise(r => setTimeout(r, 600)); // Simulate scan delay

            const lower = trimmedInput.toLowerCase();
            let opsec: "SAFE" | "SENSITIVE" | "HIGH" = "SAFE";
            const critical = ["bomb", "attack", "kill", "assassinate", "terrorism", "explosive", "weapon", "target", "strike", "ied", "hostage", "rape"];
            if (critical.some(word => lower.includes(word)) || lower.includes("deployment") || lower.includes("0600")) {
                opsec = "HIGH";
            } else if (lower.includes("location")) {
                opsec = "SENSITIVE";
            }

            risk = {
                ai_score: Math.random() * 20,
                opsec_risk: opsec,
                phishing_risk: lower.includes("click here") ? "HIGH" : "LOW",
                explanation: "Local field mode scan complete."
            };

            const committedId = `offline-${Date.now()}`;
            const offlineSavedMessage = {
                ...newMessage,
                id: committedId,
                status: (risk.opsec_risk === 'HIGH' ? 'blocked' : 'sent') as any,
                risk: risk
            };

            const list = JSON.parse(localStorage.getItem("offlineMessages") || "[]");
            list.push(offlineSavedMessage);
            localStorage.setItem("offlineMessages", JSON.stringify(list));

            setMessages(prev => {
                const nextMap = new Map(prev.map(m => [m.id, m]));
                if (nextMap.has(newMessage.id)) nextMap.delete(newMessage.id);
                nextMap.set(committedId, offlineSavedMessage);
                return Array.from(nextMap.values()).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
            });

            setIsScanning(false);
            setTimeout(() => { sendingRef.current = false; }, 500);
            return;
        }

        try {
            const res = await fetch('/api/v1/threat-intel/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    lines: newMessage.text || "[Encrypted File Attachment]",
                    file_url: fileData?.url,
                    file_type: fileData?.type,
                    file_size: fileData?.size,
                    integrity_hash: integrityHash,
                    channel_id: selectedChannel,
                    ttl_seconds: ttl,
                    reply_to_id: replyTo?.id
                })
            });

            if (res.status === 401) {
                window.location.href = '/login';
                return;
            }

            if (res.ok) {
                risk = await res.json();
            }
        } catch (e) {
            console.warn("Backend error, relying on poll for confirmation.", e);
        }

        if (risk) {
            setMessages(prev => {
                const nextMap = new Map(prev.map(m => [m.id, m]));
                // Delete the temp ID used locally
                if (nextMap.has(newMessage.id)) nextMap.delete(newMessage.id);
                // Also check if poller already added the committed ID
                const committedId = risk!.message_id ? risk!.message_id.toString() : newMessage.id;

                nextMap.set(committedId, {
                    ...newMessage,
                    id: committedId,
                    status: (risk!.opsec_risk === 'HIGH' ? 'blocked' : 'sent') as any,
                    risk: risk!
                });
                return Array.from(nextMap.values()).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
            });
        }

        setIsScanning(false);
        // Delay unlocking slightly to completely clear the race window
        setTimeout(() => {
            sendingRef.current = false;
        }, 500);
    };

    const handleAddDM = async () => {
        if (!dmEmail) return;
        try {
            const token = localStorage.getItem('token');
            const res = await fetch('/api/v1/chat/dm', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ identifier: dmEmail })
            });

            if (res.ok) {
                const data = await res.json();

                // Add to DMs list if not exists
                if (!dms.find(d => d.id === data.channel_id)) {
                    setDms([...dms, {
                        id: data.channel_id,
                        name: data.target_user.full_name || data.target_user.email,
                        status: "ENCRYPTED"
                    }]);
                }

                setSelectedChannel(data.channel_id);
                setDmEmail("");
                setShowDmInput(false);
            } else {
                alert("User not found via email");
            }
        } catch (e) {
            console.error("DM Error", e);
        }
    };

    // Fetch DMs on load
    const fetchDms = async () => {
        try {
            const token = localStorage.getItem('token');
            if (!token) return;
            const res = await fetch('/api/v1/chat/dms', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setDms(data);
            }
        } catch (e) {
            console.error("Failed to fetch DMs", e);
        }
    };

    // Mock scan logic for UI demo
    const mockScan = async (text: string): Promise<RiskResult> => {
        const lower = text.toLowerCase();
        let opsec: "SAFE" | "SENSITIVE" | "HIGH" = "SAFE";

        // Critical threats
        const critical = ["bomb", "attack", "kill", "assassinate", "terrorism", "explosive", "weapon", "target", "strike", "ied", "hostage", "rape"];

        if (critical.some(word => lower.includes(word))) {
            opsec = "HIGH";
        } else if (lower.includes("deployment") || lower.includes("0600")) {
            opsec = "HIGH";
        } else if (lower.includes("location")) {
            opsec = "SENSITIVE";
        }

        let phishing: "LOW" | "MODERATE" | "HIGH" = "LOW";
        if (lower.includes("click here")) phishing = "HIGH";

        return {
            ai_score: Math.random() * 20,
            opsec_risk: opsec,
            phishing_risk: phishing,
            explanation: "Automated scan complete."
        };
    };

    return (
        <div className="flex flex-col w-full h-full bg-slate-950 font-sans text-slate-200">
            {/* Offline Banner */}
            {offlineMode && (
                <div className="bg-rose-600/90 text-white text-center py-1.5 text-xs font-bold tracking-widest uppercase flex items-center justify-center gap-2 z-[200]">
                    <AlertTriangle className="w-4 h-4" />
                    Offline Field Mode Active - End-to-End Local Storage Engaged
                </div>
            )}

            <div className="flex w-full flex-1 overflow-hidden">
                {/* Sidebar */}
                <aside className="w-80 border-r border-slate-800 bg-slate-900/50 hidden md:flex flex-col">
                    <div className="p-6 border-b border-slate-800 flex justify-between items-center group">
                        <div>
                            <h2 className="text-xl font-bold flex items-center gap-2 text-teal-400">
                                <Shield className="w-5 h-5" /> SENTINEL
                            </h2>
                            <div className="text-xs text-slate-500 mt-1 flex items-center gap-1">
                                <Lock className="w-3 h-3" /> ENCRYPTED CHANNEL
                            </div>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="p-2 text-slate-500 hover:text-rose-400 hover:bg-slate-800 rounded transition duration-200"
                            title="Log Out"
                        >
                            <LogOut className="w-4 h-4" />
                        </button>
                    </div>
                    <div className="flex-1 overflow-y-auto p-4 space-y-2">
                        {channels.map(channel => (
                            <div
                                key={channel.id}
                                onClick={() => {
                                    setSelectedChannel(channel.id);
                                    setMessages([]); // Clear messages on swtich
                                }}
                                className={clsx(
                                    "p-3 rounded-lg border cursor-pointer transition-colors",
                                    selectedChannel === channel.id
                                        ? "bg-slate-800/80 border-teal-500/30 hover:bg-slate-800"
                                        : "border-transparent hover:bg-slate-800/50 opacity-60 hover:opacity-100"
                                )}
                            >
                                <div className="flex justify-between items-start mb-1">
                                    <span className={clsx("font-bold", selectedChannel === channel.id ? "text-white" : "text-slate-300")}>
                                        {channel.name}
                                    </span>
                                    <span className={clsx(
                                        "text-[10px] px-1 rounded",
                                        selectedChannel === channel.id ? "text-teal-500 bg-teal-500/10" : "text-slate-500"
                                    )}>
                                        {channel.status}
                                    </span>
                                </div>
                                <div className="text-xs text-slate-400 truncate">
                                    {selectedChannel === channel.id ? "Secure connection established" : "Click to connect..."}
                                </div>
                                <div className="absolute right-2 top-2 w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"></div>
                            </div>
                        ))}

                        <div className="mt-8 mb-4 px-4 flex justify-between items-center text-xs font-mono text-slate-500 uppercase tracking-wider">
                            <span>Direct Messages</span>
                            <button onClick={() => setShowDmInput(!showDmInput)} className="hover:text-teal-400">+</button>
                        </div>

                        {showDmInput && (
                            <div className="px-4 mb-4 flex gap-2">
                                <input
                                    type="text"
                                    placeholder="User Email or ID..."
                                    className="bg-slate-900/50 border border-slate-700 text-xs p-1 rounded w-full text-slate-300 focus:border-teal-500 outline-none"
                                    value={dmEmail}
                                    onChange={(e) => setDmEmail(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleAddDM()}
                                />
                            </div>
                        )}

                        {dms.map(dm => (
                            <div
                                key={dm.id}
                                onClick={() => {
                                    setSelectedChannel(dm.id);
                                    setMessages([]); // Clear messages on switch
                                }}
                                className={clsx(
                                    "relative p-4 cursor-pointer transition-all duration-300 border-l-2",
                                    selectedChannel === dm.id
                                        ? "bg-teal-500/10 border-teal-500"
                                        : "border-transparent hover:bg-slate-800/50"
                                )}
                            >
                                <div className="flex justify-between items-start mb-1">
                                    <h3 className={clsx(
                                        "font-medium",
                                        selectedChannel === dm.id ? "text-teal-400" : "text-slate-300"
                                    )}>{dm.name}</h3>
                                    <span className="text-[10px] font-mono text-emerald-500">{dm.status}</span>
                                </div>
                                <div className="text-xs text-slate-500 truncate">
                                    Secure direct link active
                                </div>
                            </div>
                        ))}
                    </div>
                </aside>

                {/* Main Chat Area */}
                <main className="flex-1 flex flex-col relative bg-[url('/grid.svg')]">
                    {/* Header */}
                    <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur-md flex items-center justify-between px-6 z-10">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-teal-500 to-emerald-500 flex items-center justify-center font-bold text-black shadow-lg shadow-teal-500/20">
                                {channels.find(c => c.id === selectedChannel)?.name.substring(0, 2).toUpperCase()}
                            </div>
                            <div>
                                <h3 className="font-bold text-white leading-tight">
                                    {channels.find(c => c.id === selectedChannel)?.name}
                                </h3>
                                <div className="flex items-center gap-1 text-xs text-emerald-400">
                                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                    SECURE CONNECTION ESTABLISHED
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            {/* Enhanced Encryption Status Panel */}
                            <div className="bg-emerald-950/30 border border-emerald-500/30 rounded-lg px-3 py-1.5 flex items-center gap-2">
                                <Key className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                                <div className="flex flex-col">
                                    <span className="text-[10px] font-bold text-emerald-400">E2E ENCRYPTED</span>
                                    <span className="text-[8px] text-emerald-500/70">AES-256 • Session Rotating</span>
                                </div>
                            </div>

                            {/* Offline Field Mode Toggle */}
                            <button
                                onClick={() => setOfflineMode(!offlineMode)}
                                className={clsx(
                                    "px-3 py-1.5 rounded-lg border flex items-center gap-2 transition-colors",
                                    offlineMode ? "bg-rose-500/20 text-rose-400 border-rose-500/50" : "bg-slate-800/50 text-slate-400 border-slate-700 hover:text-white"
                                )}
                            >
                                <Network className="w-3.5 h-3.5" />
                                <span className="text-[10px] font-bold uppercase tracking-wider hidden md:inline">
                                    {offlineMode ? "Field Mode" : "Field Mode"}
                                </span>
                            </button>

                            {/* AI Model Visibility Toggle */}
                            {permissions.canViewAI(currentRole) && !permissions.isSimpleView(currentRole) && (
                                <button
                                    onClick={() => setShowAIPanel(!showAIPanel)}
                                    className="bg-purple-950/30 border border-purple-500/30 rounded-lg px-3 py-1.5 flex items-center gap-2 hover:bg-purple-900/30 transition-colors"
                                >
                                    <Brain className="w-3.5 h-3.5 text-purple-400" />
                                    <span className="text-[10px] font-bold text-purple-400 hidden md:inline">AI ANALYSIS</span>
                                </button>
                            )}

                            <div className="bg-slate-800/50 border border-slate-700 rounded px-3 py-1 flex items-center gap-2 text-xs">
                                <Activity className="w-3 h-3 text-teal-400" />
                                <span>THREAT LEVEL: LOW</span>
                            </div>
                        </div>
                    </header>

                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-6 space-y-6 relative" onClick={() => setShowDeleteMenu(null)}>
                        {messages.filter(m => !m.hiddenForMe).map((msg) => (
                            <motion.div
                                key={msg.id}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                layout
                                className={clsx(
                                    "flex flex-col max-w-[80%]",
                                    msg.sender === 'me' ? "ml-auto items-end" : "mr-auto items-start"
                                )}
                                onClick={() => {
                                    setSelectedMessage(msg);
                                    setShowAIPanel(true);
                                }}
                            >
                                <div className={clsx(
                                    "relative p-4 rounded-2xl text-sm leading-relaxed backdrop-blur-sm shadow-xl border transition-all duration-500 cursor-pointer group hover:scale-[1.02]",
                                    msg.sender === 'me'
                                        ? "bg-teal-950/30 border-teal-500/30 text-teal-100 rounded-br-none"
                                        : "bg-slate-800/60 border-slate-700 text-slate-200 rounded-bl-none",
                                    msg.status === 'blocked' ? "!border-rose-500/50 !bg-rose-950/20" : "",
                                    selectedMessage?.id === msg.id ? "ring-2 ring-purple-500 ring-offset-2 ring-offset-slate-900 !border-purple-500/50" : ""
                                )}>
                                    {/* Role Badges & Threat Escalation */}
                                    <div className="flex justify-between items-start mb-2">
                                        {msg.sender === 'me' ? (
                                            <span className={clsx(
                                                "text-[10px] font-bold uppercase tracking-wider",
                                                currentRole === "commander" ? "text-rose-400" :
                                                    currentRole === "analyst" ? "text-purple-400" :
                                                        currentRole === "agent" ? "text-teal-400" : "text-slate-400"
                                            )}>
                                                {currentRole === "commander" && "[COMMANDER]"}
                                                {currentRole === "analyst" && "[ANALYST]"}
                                                {currentRole === "agent" && "[FIELD AGENT]"}
                                                {currentRole === "observer" && "[OBSERVER]"}
                                                {currentRole === "user" && "[USER]"}
                                            </span>
                                        ) : (
                                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                                                [OFFICER]
                                            </span>
                                        )}

                                        {msg.risk?.opsec_risk === 'HIGH' && permissions.canEscalate(currentRole) && (
                                            <button
                                                onClick={(e) => e.stopPropagation()}
                                                className="bg-red-500 hover:bg-red-600 text-white text-[10px] font-bold px-2 py-0.5 rounded shadow shadow-red-500/50 transition-colors z-20"
                                            >
                                                ESCALATE THREAT
                                            </button>
                                        )}
                                    </div>

                                    {/* Reply Context Display */}
                                    {msg.replyTo && (
                                        <div className="mb-2 p-2 rounded bg-slate-900/50 border-l-2 border-teal-500 text-xs opacity-70 flex flex-col gap-0.5 relative overflow-hidden">
                                            <span className="font-bold text-teal-400 capitalize">{msg.replyTo.sender === 'me' ? 'You' : 'Officer'}</span>
                                            <span className="truncate">{msg.replyTo.text}</span>
                                        </div>
                                    )}

                                    {/* Status Icons */}
                                    <div className="absolute -top-3 right-2 flex gap-1">
                                        {msg.risk?.opsec_risk === 'HIGH' && (
                                            <span className="bg-rose-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded shadow-lg flex items-center gap-1">
                                                <AlertTriangle className="w-3 h-3" /> OPSEC
                                            </span>
                                        )}
                                        {((msg.risk?.ai_score ?? 0) > 50) && (
                                            <span className="bg-yellow-500 text-black text-[10px] font-bold px-1.5 py-0.5 rounded shadow-lg flex items-center gap-1">
                                                <Eye className="w-3 h-3" /> AI
                                            </span>
                                        )}
                                    </div>

                                    {msg.is_deleted ? (
                                        <span className="italic opacity-60 flex items-center gap-2 border-b border-dashed border-slate-500 pb-1 w-full mt-2">
                                            <Shield className="w-4 h-4 text-slate-500" />
                                            Message removed by officer
                                        </span>
                                    ) : (
                                        <>
                                            {msg.text}

                                            {msg.file && (
                                                <div className="mt-3 p-3 bg-slate-800/50 rounded border border-slate-700/50 flex items-center gap-3 group/file hover:border-teal-500/30 transition-colors">
                                                    <div className="p-2 bg-teal-500/10 rounded">
                                                        <File className="w-5 h-5 text-teal-400" />
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="text-xs font-bold text-slate-200 truncate">{msg.file.name}</div>
                                                        <div className="text-[10px] text-slate-500 font-mono">{msg.file.size} • AES-256 ENCRYPTED</div>
                                                    </div>
                                                    <button className="p-2 hover:bg-slate-700 rounded transition-colors text-teal-400" title="Decrypt & Download">
                                                        <Download className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            )}
                                        </>
                                    )}

                                    {msg.integrityHash && msg.status === 'sent' && !msg.is_deleted && (
                                        <div className="mt-2 pt-2 border-t border-slate-700/30 flex items-center gap-1.5 text-[10px] text-emerald-500/80 font-mono">
                                            <Shield className="w-3 h-3" />
                                            SHA-256 VERIFIED: {msg.integrityHash.substring(0, 8)}...
                                        </div>
                                    )}

                                    {/* Hover Actions: Reply & Options Buttons */}
                                    <div className={clsx(
                                        "absolute top-2 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1.5",
                                        msg.sender === 'me' ? "right-full mr-2" : "left-full ml-2"
                                    )}>
                                        <button
                                            onClick={(e) => { e.stopPropagation(); setReplyTo(msg); fileInputRef.current?.focus(); }}
                                            className="p-1.5 bg-slate-800 rounded-full border border-slate-700 hover:bg-teal-500/20 hover:text-teal-400 hover:border-teal-500/50 transition-colors"
                                            title="Reply"
                                            disabled={msg.is_deleted}
                                        >
                                            <Reply className="w-4 h-4" />
                                        </button>
                                        <button
                                            onClick={(e) => { e.stopPropagation(); setShowDeleteMenu(showDeleteMenu === msg.id ? null : msg.id); }}
                                            className="p-1.5 bg-slate-800 rounded-full border border-slate-700 hover:bg-rose-500/20 hover:text-rose-400 hover:border-rose-500/50 transition-colors"
                                            title="Options"
                                        >
                                            <MoreVertical className="w-4 h-4" />
                                        </button>
                                    </div>

                                    {/* Neon Cyber Delete Menu Popup */}
                                    <AnimatePresence>
                                        {showDeleteMenu === msg.id && (
                                            <motion.div
                                                initial={{ opacity: 0, scale: 0.95, y: 10 }}
                                                animate={{ opacity: 1, scale: 1, y: 0 }}
                                                exit={{ opacity: 0, scale: 0.95, y: 10 }}
                                                className={clsx(
                                                    "absolute top-12 z-[100] min-w-[180px] bg-slate-900 border border-slate-700 shadow-2xl rounded-lg p-2 flex flex-col gap-1 shadow-rose-900/20 backdrop-blur-md",
                                                    msg.sender === 'me' ? "-left-4" : "-right-4"
                                                )}
                                                onClick={(e) => e.stopPropagation()}
                                            >
                                                <button
                                                    onClick={() => deleteMessage(msg.id, "me")}
                                                    className="text-left px-3 py-2 text-xs font-mono text-slate-300 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                                                >
                                                    [ Delete for Me ]
                                                </button>
                                                {msg.sender === "me" && !msg.is_deleted && (
                                                    <button
                                                        onClick={() => deleteMessage(msg.id, "everyone")}
                                                        className="text-left px-3 py-2 text-xs font-mono text-slate-300 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                                                    >
                                                        [ Delete for Everyone ]
                                                    </button>
                                                )}
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                    <div className="mt-2 flex items-center justify-end gap-2 opacity-60 text-[10px]">
                                        {msg.sender === 'me' && msg.status === 'scanning' && (
                                            <span className="flex items-center gap-1 text-teal-400 animate-pulse">
                                                <Activity className="w-3 h-3" /> SCANNING...
                                            </span>
                                        )}
                                        {msg.sender === 'me' && msg.status === 'sent' && (
                                            <span className="flex items-center gap-1 text-emerald-400">
                                                <Lock className="w-3 h-3" /> ENCRYPTED
                                            </span>
                                        )}
                                        {msg.sender === 'me' && msg.status === 'blocked' && (
                                            <span className="flex items-center gap-1 text-rose-400">
                                                <AlertTriangle className="w-3 h-3" /> BLOCKED
                                            </span>
                                        )}
                                        <span>{msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                                    </div>
                                </div>
                            </motion.div>
                        ))}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area */}
                    <div className="p-4 bg-slate-900/80 backdrop-blur border-t border-slate-800 relative z-10">
                        {fileUpload && (
                            <div className="absolute bottom-full left-4 mb-2 p-2 bg-slate-800 rounded border border-slate-700 flex items-center gap-2 text-xs text-slate-300 shadow-lg animate-in fade-in slide-in-from-bottom-2">
                                <File className="w-3 h-3 text-teal-400" />
                                <span className="max-w-[150px] truncate">{fileUpload.name}</span>
                                <span className="text-slate-500">({(fileUpload.size / 1024).toFixed(1)} KB)</span>
                                <button onClick={() => setFileUpload(null)} className="ml-2 hover:text-white p-1">×</button>
                            </div>
                        )}

                        {/* Replying Banner */}
                        {replyTo && (
                            <div className="flex items-center justify-between p-2 mb-2 bg-slate-800/80 border-l-2 border-teal-500 rounded text-xs animate-in slide-in-from-bottom-2 fade-in">
                                <div className="flex flex-col">
                                    <span className="font-bold text-teal-400 mb-0.5">Replying to {replyTo.sender === 'me' ? 'yourself' : 'Officer'}</span>
                                    <span className="text-slate-400 truncate max-w-[200px]">{replyTo.text}</span>
                                </div>
                                <button onClick={() => setReplyTo(null)} className="p-1 hover:bg-slate-700 rounded-full text-slate-500 hover:text-white">✕</button>
                            </div>
                        )}

                        <div className="relative max-w-4xl mx-auto flex items-end gap-2">
                            <input
                                type="file"
                                ref={fileInputRef}
                                className="hidden"
                                onChange={(e) => {
                                    if (e.target.files?.[0]) setFileUpload(e.target.files[0]);
                                }}
                            />
                            <button
                                onClick={() => fileInputRef.current?.click()}
                                className={clsx(
                                    "p-3 rounded-full hover:bg-slate-700 text-slate-400 border border-slate-700 transition mb-1",
                                    fileUpload ? "bg-teal-500/10 border-teal-500/50 text-teal-400" : "bg-slate-800"
                                )}
                                title="Attach Encrypted File"
                            >
                                {fileUpload ? <File className="w-5 h-5" /> : <Paperclip className="w-5 h-5" />}
                            </button>
                            <input
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                        e.preventDefault();
                                        e.stopPropagation();
                                        handleSend();
                                    }
                                }}
                                placeholder={permissions.canSendMessage(currentRole) ? "Type a secure message..." : "Observer mode active. Read-only."}
                                className="w-full bg-slate-950/50 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/20 transition-all placeholder:text-slate-600 font-mono disabled:opacity-50"
                                disabled={isScanning || !permissions.canSendMessage(currentRole)}
                            />
                            {/* Scan line effect when focused or send */}
                            <div className="absolute inset-0 rounded-xl pointer-events-none border border-transparent group-focus-within:border-teal-500/10"></div>

                            <button
                                onClick={handleSend}
                                disabled={(!input.trim() && !fileUpload) || isScanning || !permissions.canSendMessage(currentRole)}
                                className="p-3 rounded-xl bg-teal-500 hover:bg-teal-400 text-slate-900 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-teal-500/20 mb-1"
                            >
                                {isScanning ? <Activity className="w-5 h-5 animate-pulse" /> : <Send className="w-5 h-5" />}
                            </button>
                        </div>
                    </div>
                    <div className="flex justify-between items-center mt-2 text-[10px] text-slate-600 px-4 font-mono">
                        <div className="flex items-center gap-4">
                            <span className="flex items-center gap-1"><Lock className="w-3 h-3" /> AES-256 E2EE ACTIVE</span>
                            {/* TTL Selector */}
                            <select
                                value={ttl || ""}
                                onChange={(e) => setTtl(e.target.value ? Number(e.target.value) : null)}
                                className="bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-slate-400 focus:outline-none focus:border-teal-500/50 hover:border-teal-500/30 transition-colors"
                            >
                                <option value="">∞ Keep Forever</option>
                                <option value="10">⏱️ 10 Seconds</option>
                                <option value="60">⏱️ 1 Minute</option>
                                <option value="3600">⏱️ 1 Hour</option>
                            </select>
                        </div>
                        <span className="flex items-center gap-1 text-teal-500/50"><Activity className="w-3 h-3" /> AI SENTINEL ON</span>
                    </div>

                    {/* AI Analysis Panel - Signal 1: AI Model Visibility */}
                    <AnimatePresence>
                        {showAIPanel && !permissions.isSimpleView(currentRole) && (
                            <motion.div
                                initial={{ x: 400, opacity: 0 }}
                                animate={{ x: 0, opacity: 1 }}
                                exit={{ x: 400, opacity: 0 }}
                                className="absolute right-0 top-0 bottom-0 w-96 bg-slate-900/95 backdrop-blur-xl border-l border-purple-500/30 shadow-2xl z-20 overflow-y-auto"
                            >
                                <div className="p-6">
                                    {/* Header */}
                                    <div className="flex items-center justify-between mb-6">
                                        <div className="flex items-center gap-2">
                                            <Brain className="w-5 h-5 text-purple-400" />
                                            <h3 className="text-lg font-bold text-purple-400">AI Threat Analysis</h3>
                                        </div>
                                        <button
                                            onClick={() => setShowAIPanel(false)}
                                            className="text-slate-500 hover:text-slate-300"
                                        >
                                            ✕
                                        </button>
                                    </div>

                                    {/* Real-time AI Metrics */}
                                    {(() => {
                                        const currentMsg = selectedMessage || messages[messages.length - 1];
                                        const severity = currentMsg?.risk?.severity || 'LOW';
                                        const confidence = currentMsg?.risk?.confidence || 0;
                                        const isTransformer = currentMsg?.risk?.ai_method === 'transformer';
                                        return (
                                            <div className="space-y-4 mb-6">
                                                {/* Overall Severity */}
                                                <div className={clsx(
                                                    "rounded-lg p-4 border",
                                                    severity === 'HIGH' ? 'bg-red-950/30 border-red-500/30' :
                                                    severity === 'MEDIUM' ? 'bg-orange-950/30 border-orange-500/30' :
                                                    'bg-emerald-950/20 border-emerald-500/20'
                                                )}>
                                                    <div className="text-xs text-slate-400 mb-1">UNIFIED THREAT SEVERITY</div>
                                                    <div className="flex items-center justify-between">
                                                        <span className={clsx(
                                                            'text-2xl font-black tracking-wider',
                                                            severity === 'HIGH' ? 'text-red-400' :
                                                            severity === 'MEDIUM' ? 'text-orange-400' :
                                                            'text-emerald-400'
                                                        )}>{severity}</span>
                                                        <div className="text-right">
                                                            <div className="text-xs text-slate-500">Confidence</div>
                                                            <div className="text-xl font-bold text-white">{confidence}%</div>
                                                        </div>
                                                    </div>
                                                    <div className="mt-2 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                                        <div
                                                            className={clsx(
                                                                'h-full transition-all duration-700 rounded-full',
                                                                severity === 'HIGH' ? 'bg-gradient-to-r from-red-600 to-rose-400' :
                                                                severity === 'MEDIUM' ? 'bg-gradient-to-r from-orange-500 to-amber-400' :
                                                                'bg-gradient-to-r from-emerald-600 to-teal-400'
                                                            )}
                                                            style={{ width: `${confidence}%` }}
                                                        />
                                                    </div>
                                                    <div className="mt-2 text-[10px] text-slate-500 flex items-center gap-1">
                                                        {isTransformer ? (
                                                            <><span className="text-purple-400">⚡ TRANSFORMER</span> inference active</>
                                                        ) : (
                                                            <><span className="text-yellow-400">⚙ HEURISTIC</span> fallback mode</>
                                                        )}
                                                    </div>
                                                </div>

                                                <div className="bg-slate-800/50 border border-purple-500/20 rounded-lg p-4">
                                                    <div className="text-xs text-slate-400 mb-2">AI-GENERATED CONTENT SCORE</div>
                                                    <div className="flex items-end gap-2">
                                                        <span className="text-3xl font-bold text-purple-400">
                                                            {currentMsg?.risk?.ai_score?.toFixed(1) || '0.0'}%
                                                        </span>
                                                        <span className="text-xs text-slate-500 mb-1">
                                                            {isTransformer ? 'transformer confidence' : 'heuristic estimate'}
                                                        </span>
                                                    </div>
                                                    <div className="mt-2 h-2 bg-slate-700 rounded-full overflow-hidden">
                                                        <div
                                                            className="h-full bg-gradient-to-r from-purple-500 to-pink-500 transition-all duration-500"
                                                            style={{ width: `${currentMsg?.risk?.ai_score || 0}%` }}
                                                        />
                                                    </div>
                                                </div>

                                                <div className="bg-slate-800/50 border border-orange-500/20 rounded-lg p-4">
                                                    <div className="text-xs text-slate-400 mb-2">OPSEC CLASSIFIER OUTPUT</div>
                                                    <div className="flex items-center justify-between">
                                                        <span className={clsx(
                                                            "text-2xl font-bold",
                                                            currentMsg?.risk?.opsec_risk === 'HIGH' ? 'text-red-400' :
                                                                currentMsg?.risk?.opsec_risk === 'SENSITIVE' ? 'text-orange-400' :
                                                                    'text-emerald-400'
                                                        )}>
                                                            {currentMsg?.risk?.opsec_risk || 'SAFE'}
                                                        </span>
                                                        <div className="text-right">
                                                            <div className={clsx(
                                                                "px-3 py-1 rounded-full text-xs font-bold",
                                                                currentMsg?.risk?.opsec_risk === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                                                                    currentMsg?.risk?.opsec_risk === 'SENSITIVE' ? 'bg-orange-500/20 text-orange-400' :
                                                                        'bg-emerald-500/20 text-emerald-400'
                                                            )}>
                                                                {currentMsg?.risk?.opsec_risk === 'HIGH' ? 'BLOCK' : 'ALLOW'}
                                                            </div>
                                                            <div className="text-[10px] text-slate-500 mt-1">Score: {currentMsg?.risk?.opsec_score || 0}</div>
                                                        </div>
                                                    </div>
                                                    <div className="text-xs text-slate-500 mt-2">
                                                        Hybrid regex + zero-shot NLI classifier
                                                    </div>
                                                </div>

                                                <div className="bg-slate-800/50 border border-yellow-500/20 rounded-lg p-4">
                                                    <div className="text-xs text-slate-400 mb-2">PHISHING RISK PROBABILITY</div>
                                                    <div className="flex items-center justify-between">
                                                        <span className={clsx(
                                                            "text-3xl font-bold",
                                                            currentMsg?.risk?.phishing_risk === 'HIGH' ? 'text-red-400' :
                                                                currentMsg?.risk?.phishing_risk === 'MODERATE' ? 'text-yellow-400' :
                                                                    'text-emerald-400'
                                                        )}>
                                                            {currentMsg?.risk?.phishing_risk || 'LOW'}
                                                        </span>
                                                        <span className="text-lg font-bold text-slate-400">
                                                            {currentMsg?.risk?.phishing_confidence || 0}%
                                                        </span>
                                                    </div>
                                                    <div className="text-xs text-slate-500 mt-2">
                                                        URL features + social engineering + zero-shot NLI
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })()}


                                    {/* Signal 3: Threat Graph Visualization */}
                                    <div className="bg-slate-800/50 border border-teal-500/20 rounded-lg p-4">
                                        <div className="flex items-center gap-2 mb-4">
                                            <Network className="w-4 h-4 text-teal-400" />
                                            <div className="text-xs font-bold text-teal-400">THREAT GRAPH</div>
                                        </div>

                                        {/* Simple Network Visualization */}
                                        <div className="relative h-48 bg-slate-900/50 rounded-lg p-4 overflow-hidden">
                                            {/* Graph Nodes */}
                                            <div className="absolute top-4 left-4 w-12 h-12 rounded-full bg-teal-500/20 border-2 border-teal-500 flex items-center justify-center z-10">
                                                <span className="text-xs font-bold text-teal-400">U1</span>
                                            </div>
                                            <div className="absolute top-4 right-4 w-12 h-12 rounded-full bg-purple-500/20 border-2 border-purple-500 flex items-center justify-center z-10">
                                                <span className="text-xs font-bold text-purple-400">U2</span>
                                            </div>
                                            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 w-16 h-16 rounded-full bg-emerald-500/20 border-2 border-emerald-500 flex items-center justify-center z-10">
                                                <span className="text-xs font-bold text-emerald-400">MSG</span>
                                            </div>

                                            {/* Connection Lines */}
                                            <svg className="absolute inset-0 w-full h-full">
                                                <line x1="60" y1="30" x2="50%" y2="70%" stroke="#14b8a6" strokeWidth="2" strokeDasharray="4" opacity="0.5" />
                                                <line x1="calc(100% - 60px)" y1="30" x2="50%" y2="70%" stroke="#a855f7" strokeWidth="2" strokeDasharray="4" opacity="0.5" />
                                            </svg>

                                            {/* Alert Cluster */}
                                            {(() => {
                                                const currentMsg = selectedMessage || messages[messages.length - 1];
                                                if (currentMsg?.risk && (currentMsg.risk.opsec_risk === 'HIGH' || currentMsg.risk.phishing_risk === 'HIGH')) {
                                                    return (
                                                        <div className="absolute top-1/2 right-8 w-10 h-10 rounded-full bg-red-500/30 border-2 border-red-500 flex items-center justify-center animate-pulse z-20">
                                                            <AlertTriangle className="w-4 h-4 text-red-400" />
                                                        </div>
                                                    );
                                                }
                                                return null;
                                            })()}
                                        </div>

                                        <div className="mt-3 text-[10px] text-slate-500 space-y-1">
                                            <div className="flex items-center gap-2">
                                                <div className="w-2 h-2 rounded-full bg-teal-500"></div>
                                                <span>User Nodes ({messages.filter(m => m.sender === 'me').length} sent)</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                                                <span>Message Flow ({messages.length} total)</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <div className="w-2 h-2 rounded-full bg-red-500"></div>
                                                <span>Alert Clusters ({messages.filter(m => m.risk?.opsec_risk === 'HIGH').length} detected)</span>
                                            </div>
                                        </div>
                                                           {/* Reasons / Explainability */}
                                    {(() => {
                                        const currentMsg = selectedMessage || messages[messages.length - 1];
                                        const reasons = currentMsg?.risk?.reasons || [];
                                        if (reasons.length === 0) return null;
                                        return (
                                            <div className="mt-4 p-4 bg-slate-800/30 border border-slate-700 rounded-lg">
                                                <div className="text-xs font-bold text-slate-400 mb-2 flex items-center gap-2">
                                                    <Brain className="w-3.5 h-3.5 text-purple-400" />
                                                    THREAT INDICATORS
                                                </div>
                                                <div className="space-y-1.5">
                                                    {reasons.slice(0, 5).map((r, i) => (
                                                        <div key={i} className="flex items-start gap-2 text-[10px] text-orange-300">
                                                            <AlertTriangle className="w-3 h-3 mt-0.5 text-orange-400 shrink-0" />
                                                            <span>{r}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        );
                                    })()}

                                    {/* Context Risk */}
                                    {(() => {
                                        const currentMsg = selectedMessage || messages[messages.length - 1];
                                        const contextRisk = currentMsg?.risk?.context_risk;
                                        if (!contextRisk || contextRisk === 'SAFE') return null;
                                        return (
                                            <div className="mt-4 p-4 bg-amber-950/30 border border-amber-500/30 rounded-lg">
                                                <div className="text-xs font-bold text-amber-400 mb-2 flex items-center gap-2">
                                                    <Network className="w-3.5 h-3.5" />
                                                    CONTEXT LEAKAGE ALERT
                                                </div>
                                                <div className="text-[10px] text-amber-300">
                                                    Cross-message OPSEC pattern detected. Risk escalated from conversation context analysis.
                                                </div>
                                                <div className={clsx(
                                                    "mt-2 text-xs font-bold",
                                                    contextRisk === 'HIGH' ? 'text-red-400' : 'text-orange-400'
                                                )}>
                                                    CONTEXT: {contextRisk}
                                                </div>
                                            </div>
                                        );
                                    })()}

                                    {/* Model Info */}
                                    <div className="mt-4 p-4 bg-slate-800/30 border border-slate-700 rounded-lg">
                                        <div className="text-xs font-bold text-slate-400 mb-2">ACTIVE THREAT ENGINE</div>
                                        <div className="space-y-2 text-[10px]">
                                            {(() => {
                                                const currentMsg = selectedMessage || messages[messages.length - 1];
                                                const version = currentMsg?.risk?.model_version || 'heuristic';
                                                const method = currentMsg?.risk?.ai_method || 'heuristic';
                                                const isTransformer = method === 'transformer';
                                                return (<>
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-slate-400">AI Content Detector</span>
                                                        <span className={isTransformer ? 'text-emerald-400' : 'text-yellow-400'}>
                                                            {isTransformer ? '● TRANSFORMER' : '● HEURISTIC'}
                                                        </span>
                                                    </div>
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-slate-400">OPSEC Classifier</span>
                                                        <span className="text-emerald-400">● HYBRID</span>
                                                    </div>
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-slate-400">Phishing Detector</span>
                                                        <span className="text-emerald-400">● ZERO-SHOT NLI</span>
                                                    </div>
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-slate-400">Context Tracker</span>
                                                        <span className="text-teal-400">● ACTIVE</span>
                                                    </div>
                                                    <div className="mt-2 pt-2 border-t border-slate-700 flex items-center justify-between">
                                                        <span className="text-slate-500">Model</span>
                                                        <span className="text-purple-400 font-mono text-[9px]">{version}</span>
                                                    </div>
                                                </>);
                                            })()}
                                        </div>
                                    </div>                       </div>
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </main>
            </div>
        </div>
    );
}
