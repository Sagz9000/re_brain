'use client';

import { useState, useEffect } from 'react';
import { Search, Code } from 'lucide-react';

interface FunctionTableProps {
    file: string;
}

interface FuncInfo {
    name: string;
    address: string;
    signature: string;
}

export default function FunctionTable({ file }: FunctionTableProps) {
    const [functions, setFunctions] = useState<FuncInfo[]>([]);
    const [filtered, setFiltered] = useState<FuncInfo[]>([]);
    const [search, setSearch] = useState('');
    const [loading, setLoading] = useState(false);

    const API_URL = 'http://localhost:8005';

    useEffect(() => {
        const fetchFuncs = async () => {
            setLoading(true);
            try {
                const res = await fetch(`${API_URL}/binary/${file}/functions`);
                const data = await res.json();
                if (Array.isArray(data)) {
                    setFunctions(data);
                    setFiltered(data);
                }
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        };
        fetchFuncs();
    }, [file]);

    useEffect(() => {
        const query = search.toLowerCase();
        setFiltered(functions.filter(f =>
            f.name.toLowerCase().includes(query) ||
            f.address.toLowerCase().includes(query)
        ));
    }, [search, functions]);

    return (
        <div className="flex-1 flex flex-col h-full bg-[#050505] overflow-hidden">
            {/* Toolbar */}
            <div className="h-14 border-b border-white/5 flex items-center justify-between px-6 shrink-0">
                <div className="flex items-center gap-2">
                    <Code size={18} className="text-indigo-500" />
                    <span className="font-semibold text-zinc-200">Analyzed Functions</span>
                    <span className="text-xs bg-zinc-800 px-2 py-0.5 rounded-full text-zinc-400">{filtered.length}</span>
                </div>
                <div className="relative w-64">
                    <Search className="absolute left-3 top-2.5 text-zinc-500" size={14} />
                    <input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Filter by name..."
                        className="w-full bg-zinc-900 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-200 focus:ring-1 focus:ring-indigo-500 hover:bg-zinc-800/50 transition-colors"
                    />
                </div>
            </div>

            {/* Table Header */}
            <div className="grid grid-cols-12 gap-4 px-6 py-2 border-b border-white/5 bg-zinc-900/30 text-xs font-bold text-zinc-500 uppercase tracking-wider shrink-0">
                <div className="col-span-2">Address</div>
                <div className="col-span-3">Name</div>
                <div className="col-span-7">Signature</div>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-zinc-800">
                {loading ? (
                    <div className="text-zinc-500 p-10 text-center">Loading Symbols...</div>
                ) : (
                    filtered.map((f, i) => (
                        <div key={i} className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-white/5 hover:bg-white/5 text-sm transition-colors cursor-pointer group">
                            <div className="col-span-2 font-mono text-zinc-400 group-hover:text-zinc-200">{f.address}</div>
                            <div className="col-span-3 font-medium text-zinc-300 group-hover:text-indigo-400 truncate" title={f.name}>{f.name}</div>
                            <div className="col-span-7 font-mono text-xs text-zinc-500 truncate mt-0.5 group-hover:text-zinc-300" title={f.signature}>{f.signature}</div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
