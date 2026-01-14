'use client';

import { useState, useEffect } from 'react';
import { Type, Search, RefreshCw, Filter } from 'lucide-react';
import { API_URL } from '../utils';

interface StringsViewerProps {
    file: string | null;
    onAddressClick?: (addr: string) => void;
    initialFilter?: string;
}

interface StringEntry {
    offset: string;
    value: string;
}

export default function StringsViewer({ file, onAddressClick, initialFilter }: StringsViewerProps) {
    const [strings, setStrings] = useState<StringEntry[]>([]);
    const [loading, setLoading] = useState(false);
    const [filter, setFilter] = useState(initialFilter || '');

    useEffect(() => {
        if (initialFilter) setFilter(initialFilter);
    }, [initialFilter]);


    const fetchStrings = async () => {
        if (!file) return;
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/strings`);
            const data = await res.json();
            if (Array.isArray(data)) setStrings(data);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStrings();
    }, [file]);

    const filtered = strings.filter(s => s.value.toLowerCase().includes(filter.toLowerCase()));

    return (
        <div className="flex-1 flex flex-col min-h-0 bg-[#0c0c0e]">
            {/* Toolbar */}
            <div className="h-10 border-b border-white/5 bg-[#121214] flex items-center px-4 gap-4">
                <div className="flex items-center gap-2">
                    <Type size={14} className="text-indigo-400" />
                    <span className="text-xs font-bold text-zinc-300 uppercase tracking-widest">Defined Strings</span>
                </div>

                <div className="flex-1 max-w-sm relative">
                    <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                    <input
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        placeholder="Filter strings..."
                        className="w-full bg-zinc-800/50 border border-white/5 rounded pl-8 pr-3 py-1 text-xs text-zinc-300 focus:outline-none focus:border-indigo-500/50"
                    />
                </div>

                <button
                    onClick={fetchStrings}
                    className="p-1.5 text-zinc-500 hover:text-white transition-colors ml-auto"
                >
                    <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            {/* List */}
            <div className="flex-1 overflow-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                    <thead className="sticky top-0 bg-[#0c0c0e] z-10 shadow-sm">
                        <tr className="border-b border-white/5">
                            <th className="px-4 py-2 text-zinc-500 font-medium w-12 italic">#</th>
                            <th className="px-4 py-2 text-zinc-500 font-medium w-24">Offset</th>
                            <th className="px-4 py-2 text-zinc-500 font-medium">Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((s, i) => (
                            <tr key={i} className="border-b border-white/[0.02] hover:bg-white/[0.02] transition-colors group">
                                <td className="px-4 py-1.5 text-zinc-600 tabular-nums">{i + 1}</td>
                                <td className="px-4 py-1.5 text-zinc-500">{s.offset}</td>
                                <td className="px-4 py-1.5 text-zinc-300 break-all">{s.value}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {filtered.length === 0 && !loading && (
                    <div className="p-8 text-center text-zinc-600 italic">No strings found matching filter</div>
                )}
            </div>

            {/* Footer */}
            <div className="h-6 border-t border-white/5 bg-[#09090b] flex items-center px-3">
                <span className="text-[10px] text-zinc-500">
                    Showing {filtered.length} of {strings.length} strings
                </span>
            </div>
        </div>
    );
}
