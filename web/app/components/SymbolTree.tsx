'use client';

import { ListTree, FunctionSquare, Globe, ArrowDownToLine, RefreshCw, Box } from 'lucide-react';
import { useState, useEffect } from 'react';

interface SymbolData {
    functions: { name: string; address: string; size: number }[];
    imports: { name: string; address: string }[];
    exports: { name: string; address: string }[];
}

interface SymbolTreeProps {
    file: string | null;
    onSelectFunction?: (func: { name: string, address: string }) => void;
}

export default function SymbolTree({ file, onSelectFunction }: SymbolTreeProps) {
    const [data, setData] = useState<SymbolData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState({ functions: true, imports: false, exports: false });

    const fetchSymbols = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`http://localhost:8005/binary/${file}/symbols`);
            if (!res.ok) throw new Error("Failed to fetch symbols");
            const jsonData = await res.json();
            if (jsonData.error) throw new Error(jsonData.error);
            setData(jsonData);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSymbols();
    }, [file]);

    const toggle = (section: keyof typeof expanded) => {
        setExpanded(prev => ({ ...prev, [section]: !prev[section] }));
    };

    if (!file) {
        return (
            <div className="flex-1 overflow-auto p-4 flex flex-col items-center justify-center text-zinc-500">
                <ListTree size={32} className="opacity-20 mb-2" />
                <span className="text-xs">No active binary</span>
            </div>
        );
    }

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono text-sm overflow-auto p-2">
            <div className="space-y-1">
                {/* Header */}
                <div className="flex items-center justify-between px-2 py-1 text-zinc-100 font-bold bg-white/5 rounded border border-white/5 mb-2">
                    <div className="flex items-center gap-2">
                        <ListTree size={14} className="text-indigo-400" />
                        <span className="truncate max-w-[150px]">Symbol Tree</span>
                    </div>
                    <button onClick={fetchSymbols} className="text-zinc-500 hover:text-white" title="Refresh Symbols">
                        <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                    </button>
                </div>

                {error && <div className="text-red-400 text-xs px-2 py-1">{error}</div>}

                {/* Functions */}
                <div>
                    <div
                        className="flex items-center gap-2 px-2 py-1 hover:bg-white/5 rounded cursor-pointer text-zinc-400 hover:text-zinc-200"
                        onClick={() => toggle('functions')}
                    >
                        <FunctionSquare size={12} />
                        <span className="text-xs font-bold uppercase tracking-wider">Functions</span>
                        <span className="text-[10px] text-zinc-600 ml-auto">{data?.functions?.length || 0}</span>
                    </div>
                    {expanded.functions && data?.functions && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {data.functions.map((f, i) => (
                                <div
                                    key={i}
                                    className="flex items-center justify-between group px-1 rounded hover:bg-indigo-500/10 cursor-pointer"
                                    onClick={() => onSelectFunction && onSelectFunction(f)}
                                >
                                    <span className="text-[10px] text-zinc-400 group-hover:text-indigo-300 truncate max-w-[140px]" title={f.name}>{f.name}</span>
                                    <span className="text-[9px] text-zinc-600">{f.address}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Imports */}
                <div>
                    <div
                        className="flex items-center gap-2 px-2 py-1 hover:bg-white/5 rounded cursor-pointer text-zinc-400 hover:text-zinc-200"
                        onClick={() => toggle('imports')}
                    >
                        <ArrowDownToLine size={12} />
                        <span className="text-xs font-bold uppercase tracking-wider">Imports</span>
                        <span className="text-[10px] text-zinc-600 ml-auto">{data?.imports?.length || 0}</span>
                    </div>
                    {expanded.imports && data?.imports && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {data.imports.map((imp, i) => (
                                <div key={i} className="flex items-center justify-between px-1">
                                    <span className="text-[10px] text-zinc-500 truncate max-w-[140px]" title={imp.name}>{imp.name}</span>
                                    <span className="text-[9px] text-zinc-700">{imp.address}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Exports */}
                <div>
                    <div
                        className="flex items-center gap-2 px-2 py-1 hover:bg-white/5 rounded cursor-pointer text-zinc-400 hover:text-zinc-200"
                        onClick={() => toggle('exports')}
                    >
                        <Globe size={12} />
                        <span className="text-xs font-bold uppercase tracking-wider">Exports</span>
                        <span className="text-[10px] text-zinc-600 ml-auto">{data?.exports?.length || 0}</span>
                    </div>
                    {expanded.exports && data?.exports && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {data.exports.map((exp, i) => (
                                <div key={i} className="flex items-center justify-between px-1">
                                    <span className="text-[10px] text-emerald-500/70 truncate max-w-[140px]" title={exp.name}>{exp.name}</span>
                                    <span className="text-[9px] text-zinc-700">{exp.address}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

            </div>
        </div>
    );
}
