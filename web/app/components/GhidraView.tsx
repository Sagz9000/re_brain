import React, { useState } from 'react';
import { RefreshCw, Check, AlertTriangle, Play, Bug } from 'lucide-react';
import { API_URL } from '../utils';

interface GhidraViewProps {
    vncUrl?: string; // Optional override
    activeFile?: string | null;
}

export default function GhidraView({ vncUrl, activeFile }: GhidraViewProps) {
    const [isSyncing, setIsSyncing] = useState(false);
    const [syncStatus, setSyncStatus] = useState<'idle' | 'success' | 'error'>('idle');

    const handleSync = async () => {
        if (!activeFile) return;
        setIsSyncing(true);
        setSyncStatus('idle');
        try {
            const res = await fetch(`${API_URL}/binary/${activeFile}/sync`, { method: 'POST' });
            const data = await res.json();
            if (data.status === 'success') {
                setSyncStatus('success');
            } else {
                setSyncStatus('error');
            }
        } catch (e) {
            setSyncStatus('error');
        } finally {
            setIsSyncing(false);
            setTimeout(() => setSyncStatus('idle'), 3000);
        }
    };

    const handleTriggerBridge = async () => {
        if (!activeFile) return;
        try {
            await fetch(`${API_URL}/binary/${activeFile}/bridge/trigger`, { method: 'POST' });
        } catch (e) { console.error(e); }
    };

    const handleSendToDebugger = async () => {
        if (!activeFile) return;
        try {
            await fetch(`${API_URL}/binary/${activeFile}/debug`, { method: 'POST' });
        } catch (e) { console.error(e); }
    };

    // Default to localhost:6080 with password
    const url = vncUrl || "http://localhost:6080/vnc.html?autoconnect=true&resize=scale&password=ghidra";

    return (
        <div className="w-full h-full flex flex-col bg-black">
            <div className="bg-[#2d2d30] px-2 py-1 text-xs text-zinc-400 border-b border-black flex justify-between items-center h-8 gap-2">
                <div className="flex items-center gap-2 overflow-hidden">
                    <span className="shrink-0">Session: re-ghidra2</span>
                    {activeFile && (
                        <div className="flex items-center gap-2">
                            <button
                                onClick={handleSync}
                                disabled={isSyncing}
                                title="Sync binary to Ghidra project"
                                className={`flex items-center gap-1 px-2 py-0.5 rounded transition-colors whitespace-nowrap ${syncStatus === 'success' ? 'bg-green-500/20 text-green-400' :
                                    syncStatus === 'error' ? 'bg-red-500/20 text-red-400' :
                                        'bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/40'
                                    }`}
                            >
                                {isSyncing ? <RefreshCw size={12} className="animate-spin" /> :
                                    syncStatus === 'success' ? <Check size={12} /> :
                                        syncStatus === 'error' ? <AlertTriangle size={12} /> :
                                            <RefreshCw size={12} />
                                }
                                <span>Sync to GUI</span>
                            </button>

                            <button
                                onClick={handleSendToDebugger}
                                title="Open binary in Ghidra Debugger tool"
                                className="flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/20 hover:bg-amber-500/40 text-amber-500 transition-colors whitespace-nowrap"
                            >
                                <Bug size={10} />
                                <span>Send to Debugger</span>
                            </button>

                            <button
                                onClick={handleTriggerBridge}
                                title="Manual trigger for LiveBridge (Use if sync fails)"
                                className="flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-700 hover:bg-zinc-600 text-zinc-300 transition-colors whitespace-nowrap"
                            >
                                <Play size={10} />
                                <span>Start Bridge</span>
                            </button>
                        </div>
                    )}
                </div>
                <span>{url}</span>
            </div>
            <iframe
                src={url}
                className="w-full h-full border-0"
                allowFullScreen
                title="Ghidra VNC"
            />
        </div>
    );
}
