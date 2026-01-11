'use client';

import { ListTree, FunctionSquare, Globe, ArrowDownToLine, RefreshCw, Box, Edit2, Search, X } from 'lucide-react';
import { useState, useEffect } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8005';

interface SymbolData {
    functions: { name: string; address: string; size: number }[];
    imports: { name: string; address: string }[];
    exports: { name: string; address: string }[];
}

interface SymbolTreeProps {
    file: string | null;
    onSelectFunction?: (func: { name: string, address: string }) => void;
    selectedAddress?: string | null;
}

export default function SymbolTree({ file, onSelectFunction, selectedAddress }: SymbolTreeProps) {
    const [data, setData] = useState<SymbolData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState({ functions: true, imports: false, exports: false });
    const [searchQuery, setSearchQuery] = useState('');

    const filteredData = data ? {
        functions: data.functions.filter(f => f.name.toLowerCase().includes(searchQuery.toLowerCase()) || f.address.toLowerCase().includes(searchQuery.toLowerCase())),
        imports: data.imports.filter(i => i.name.toLowerCase().includes(searchQuery.toLowerCase()) || i.address.toLowerCase().includes(searchQuery.toLowerCase())),
        exports: data.exports.filter(e => e.name.toLowerCase().includes(searchQuery.toLowerCase()) || e.address.toLowerCase().includes(searchQuery.toLowerCase()))
    } : null;

    useEffect(() => {
        if (searchQuery) {
            setExpanded({ functions: true, imports: true, exports: true });
        }
    }, [searchQuery]);

    // Sync selectedAddress to search
    useEffect(() => {
        if (selectedAddress) {
            setSearchQuery(selectedAddress);
        }
    }, [selectedAddress]);

    const fetchSymbols = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/symbols`);
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

    const handleRename = async (oldName: string, address: string) => {
        const newName = window.prompt(`Rename function '${oldName}' to:`, oldName);
        if (!newName || newName === oldName) return;

        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/rename`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    function: oldName,
                    new_name: newName,
                    address: address
                })
            });
            const result = await res.json();
            if (result.status === 'success') {
                fetchSymbols();
            } else {
                alert(`Rename failed: ${result.error || 'Unknown error'}`);
            }
        } catch (e) {
            alert(`Rename failed: ${e}`);
        } finally {
            setLoading(false);
        }
    };

    if (!file) {
        return (
            <div className="flex-1 overflow-auto p-4 flex flex-col items-center justify-center text-zinc-500">
                <ListTree size={32} className="opacity-20 mb-2" />
                <span className="text-xs">No active binary</span>
                <span className="text-[10px] text-zinc-600 mt-1">Open a file to search symbols</span>
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

                {/* Search Bar */}
                <div className="px-2 mb-2">
                    <div className="relative">
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Search symbols..."
                            className="w-full bg-black/20 border border-white/10 rounded px-7 py-1 text-xs text-zinc-300 focus:outline-none focus:border-indigo-500/50 placeholder:text-zinc-700"
                        />
                        <Search size={10} className="absolute left-2 top-1.5 text-zinc-500" />
                        {searchQuery && (
                            <button
                                onClick={() => setSearchQuery('')}
                                className="absolute right-2 top-1.5 text-zinc-500 hover:text-zinc-300"
                            >
                                <X size={10} />
                            </button>
                        )}
                    </div>
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
                        <span className="text-[10px] text-zinc-600 ml-auto">{filteredData?.functions?.length || 0}</span>
                    </div>
                    {expanded.functions && filteredData?.functions && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {filteredData.functions.map((f, i) => (
                                <div
                                    key={i}
                                    className="flex items-center justify-between group px-1 rounded hover:bg-indigo-500/10 cursor-pointer"
                                    onClick={() => onSelectFunction && onSelectFunction(f)}
                                >
                                    <div className="flex items-center gap-2 overflow-hidden">
                                        <span className="text-[10px] text-zinc-400 group-hover:text-indigo-300 truncate max-w-[120px]" title={f.name}>{f.name}</span>
                                        <button
                                            onClick={(e) => { e.stopPropagation(); handleRename(f.name, f.address); }}
                                            className="opacity-0 group-hover:opacity-100 p-0.5 hover:bg-white/10 rounded transition-all text-zinc-500 hover:text-indigo-400"
                                            title="Rename Function"
                                        >
                                            <Edit2 size={10} />
                                        </button>
                                    </div>
                                    <span className="text-[9px] text-zinc-600 shrink-0">{f.address}</span>
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
                        <span className="text-[10px] text-zinc-600 ml-auto">{filteredData?.imports?.length || 0}</span>
                    </div>
                    {expanded.imports && filteredData?.imports && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {filteredData.imports.map((imp, i) => (
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
                        <span className="text-[10px] text-zinc-600 ml-auto">{filteredData?.exports?.length || 0}</span>
                    </div>
                    {expanded.exports && filteredData?.exports && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {filteredData.exports.map((exp, i) => (
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
