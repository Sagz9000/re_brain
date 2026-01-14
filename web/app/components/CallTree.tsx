'use client';

import { GitCommit, RefreshCw, ArrowUpRight, ArrowDownLeft, Crosshair, CircleDot } from 'lucide-react';
import { useState, useEffect } from 'react';
import { API_URL } from '../utils';

interface FuncNode {
    name: string;
    address: string;
}

interface CallGraphData {
    current: FuncNode | null;
    callers: FuncNode[];
    callees: FuncNode[];
}

interface CallTreeProps {
    file: string | null;
    functionName?: string | null;
    onSelectFunction?: (func: { name: string, address: string }) => void;
}

export default function CallTree({ file, onSelectFunction }: CallTreeProps) {
    // We fetch the entire map as a list of nodes, then process it locally
    const [rawMap, setRawMap] = useState<any[]>([]);
    const [currentFunc, setCurrentFunc] = useState<FuncNode | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchGraph = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/calltree`);
            if (!res.ok) throw new Error("Failed to fetch call graph");
            const jsonData = await res.json();
            if (jsonData.error) throw new Error(jsonData.error);

            // Backend returns List<{name, address, calls: [{name, address}]}>
            setRawMap(jsonData);

            // Set default current (e.g. "entry" or first one)
            if (jsonData.length > 0) {
                // Try to find "entry" or "main"
                const entry = jsonData.find((f: any) => f.name.toLowerCase().includes('entry') || f.name.toLowerCase() === 'main') || jsonData[0];
                setCurrentFunc({ name: entry.name, address: entry.address });
            }
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchGraph();
    }, [file]);

    // Derived State: Calculate Callers/Callees for currentFunc
    const graphData: CallGraphData | null = currentFunc ? (() => {
        // 1. Find Current Node details
        const currentNodeRaw = rawMap.find(f => f.address === currentFunc.address);

        // 2. Callees: Direct lookup from raw map
        const callees: FuncNode[] = currentNodeRaw?.calls || [];

        // 3. Callers: Scan entire map to see who calls Current
        const callers: FuncNode[] = rawMap.filter(f =>
            f.calls.some((c: any) => c.address === currentFunc.address)
        ).map(f => ({ name: f.name, address: f.address }));

        return {
            current: currentFunc,
            callers: callers,
            callees: callees
        };
    })() : null;

    const handleNodeClick = (f: FuncNode) => {
        setCurrentFunc(f);
        if (onSelectFunction) onSelectFunction(f);
    };

    if (!file) {
        return (
            <div className="flex-1 overflow-auto p-4 flex flex-col items-center justify-center text-zinc-500">
                <GitCommit size={32} className="opacity-20 mb-2" />
                <span className="text-xs">No active binary</span>
            </div>
        );
    }

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono text-sm overflow-auto p-2">
            <div className="flex items-center justify-between px-2 py-1 text-zinc-100 font-bold bg-white/5 rounded border border-white/5 mb-2">
                <div className="flex items-center gap-2">
                    <GitCommit size={14} className="text-indigo-400" />
                    <span className="truncate max-w-[150px]">Call Graph</span>
                </div>
                <button onClick={fetchGraph} className="text-zinc-500 hover:text-white" title="Refresh Graph">
                    <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            {error && <div className="text-red-400 text-xs px-2 py-1">{error}</div>}

            {graphData?.current && (
                <div className="space-y-4">
                    {/* Callers */}
                    <div>
                        <div className="flex items-center gap-2 px-2 py-1 text-zinc-400 text-xs font-bold uppercase tracking-wider mb-1">
                            <ArrowDownLeft size={12} />
                            <span>Callers ({graphData.callers.length})</span>
                        </div>
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 space-y-1">
                            {graphData.callers.length === 0 && <span className="text-zinc-600 text-[10px] italic">No known callers in sample</span>}
                            {graphData.callers.map((f, i) => (
                                <div
                                    key={i}
                                    className="flex items-center justify-between group px-1 rounded hover:bg-white/5 cursor-pointer"
                                    onClick={() => handleNodeClick(f)}
                                >
                                    <span className="text-[10px] text-zinc-400 group-hover:text-amber-300 truncate max-w-[140px]" title={f.name}>{f.name}</span>
                                    <span className="text-[9px] text-zinc-600">{f.address}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Current Function */}
                    <div className="bg-indigo-500/10 border border-indigo-500/30 rounded p-2 mx-2 flex items-center gap-2">
                        <CircleDot size={14} className="text-indigo-400 animate-pulse" />
                        <div className="flex flex-col min-w-0">
                            <span className="text-xs font-bold text-indigo-200 truncate" title={graphData.current.name}>{graphData.current.name}</span>
                            <span className="text-[10px] text-indigo-400/70">{graphData.current.address}</span>
                        </div>
                    </div>

                    {/* Callees */}
                    <div>
                        <div className="flex items-center gap-2 px-2 py-1 text-zinc-400 text-xs font-bold uppercase tracking-wider mb-1">
                            <ArrowUpRight size={12} />
                            <span>Callees ({graphData.callees.length})</span>
                        </div>
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 space-y-1">
                            {graphData.callees.length === 0 && <span className="text-zinc-600 text-[10px] italic">Leaf function (no calls)</span>}
                            {graphData.callees.map((f, i) => (
                                <div
                                    key={i}
                                    className="flex items-center justify-between group px-1 rounded hover:bg-white/5 cursor-pointer"
                                    onClick={() => handleNodeClick(f)}
                                >
                                    <span className="text-[10px] text-zinc-400 group-hover:text-emerald-300 truncate max-w-[140px]" title={f.name}>{f.name}</span>
                                    <span className="text-[9px] text-zinc-600">{f.address}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
