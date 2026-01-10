'use client';

import { useState, useEffect } from 'react';
import { Activity, Terminal, Shield, Cpu, RefreshCw } from 'lucide-react';

interface LogEvent {
    time: string;
    message: string;
    source: string;
}

export default function ActivityLog() {
    const [logs, setLogs] = useState<LogEvent[]>([]);
    const [isExpanded, setIsExpanded] = useState(true);

    const fetchLogs = async () => {
        try {
            const res = await fetch('http://localhost:8005/activity');
            if (res.ok) {
                const data = await res.json();
                setLogs(data.reverse()); // Show newest first
            }
        } catch (e) {
            console.error("Failed to fetch logs:", e);
        }
    };

    useEffect(() => {
        fetchLogs();
        const interval = setInterval(fetchLogs, 3000); // Poll every 3 seconds
        return () => clearInterval(interval);
    }, []);

    const getSourceIcon = (source: string) => {
        switch (source.toLowerCase()) {
            case 'ai': return <Cpu size={12} className="text-indigo-400" />;
            case 'user': return <Shield size={12} className="text-emerald-400" />;
            default: return <Terminal size={12} className="text-zinc-500" />;
        }
    };

    return (
        <div className="flex flex-col h-full bg-[#0a0a0c]/50 flex-1 overflow-hidden">
            {/* Log List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-[10px] scrollbar-thin scrollbar-thumb-zinc-800">
                {logs.length === 0 && (
                    <div className="h-full flex flex-col items-center justify-center text-zinc-600 gap-2 opacity-50">
                        <RefreshCw size={24} className="animate-spin" />
                        <span>Awaiting system events...</span>
                    </div>
                )}
                {logs.map((log, i) => (
                    <div key={i} className="flex gap-3 group border-l border-white/5 pl-3 py-1">
                        <span className="text-zinc-600 tabular-nums">{log.time}</span>
                        <div className="flex-1 space-y-1">
                            <div className="flex items-center gap-1.5">
                                {getSourceIcon(log.source)}
                                <span className={`font-bold ${log.source === 'AI' ? 'text-indigo-400/80' : log.source === 'User' ? 'text-emerald-400/80' : 'text-zinc-500'}`}>
                                    {log.source.toUpperCase()}
                                </span>
                            </div>
                            <p className="text-zinc-300 leading-relaxed group-hover:text-white transition-colors">
                                {log.message}
                            </p>
                        </div>
                    </div>
                ))}
            </div>

            {/* Footer */}
            <div className="px-4 py-2 bg-black/40 border-t border-white/5 flex items-center justify-between text-[9px] text-zinc-600 font-mono">
                <span>LIVE STREAM</span>
                <div className="flex items-center gap-1">
                    <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                    <span>CONNECTED</span>
                </div>
            </div>
        </div>
    );
}
