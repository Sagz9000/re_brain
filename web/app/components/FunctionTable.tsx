'use client';

import { useState, useEffect } from 'react';
import { FileCode, Search, RefreshCw } from 'lucide-react';

interface FunctionData {
    name: string;
    address: string;
    signature: string;
}

interface FunctionTableProps {
    file: string;
    onSelectFunction?: (func: { name: string, address: string }) => void;
}

export default function FunctionTable({ file, onSelectFunction }: FunctionTableProps) {
    const [functions, setFunctions] = useState<FunctionData[]>([]);
    const [loading, setLoading] = useState(false);
    const [search, setSearch] = useState('');

    const fetchFunctions = async () => {
        if (!file) return;
        setLoading(true);
        try {
            const res = await fetch(`http://localhost:8005/binary/${file}/functions`);
            const data = await res.json();
            if (Array.isArray(data)) setFunctions(data);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchFunctions();
    }, [file]);

    const filtered = functions.filter(f =>
        f.name.toLowerCase().includes(search.toLowerCase()) ||
        f.address.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div className="flex-1 flex flex-col min-h-0 bg-[#0c0c0e]">
            {/* Toolbar */}
            <div className="h-10 border-b border-white/5 bg-[#121214] flex items-center px-4 gap-4">
                <div className="flex items-center gap-2">
                    <FileCode size={14} className="text-indigo-400" />
                    <span className="text-xs font-bold text-zinc-300 uppercase tracking-widest">Symbol Tree</span>
                </div>

                <div className="flex-1 max-w-sm relative">
                    <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                    <input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Filter symbols..."
                        className="w-full bg-zinc-800/50 border border-white/5 rounded pl-8 pr-3 py-1 text-xs text-zinc-300 focus:outline-none focus:border-indigo-500/50"
                    />
                </div>

                <button onClick={fetchFunctions} className="p-1.5 text-zinc-500 hover:text-white transition-colors ml-auto">
                    <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            <div className="flex-1 overflow-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                    <thead className="sticky top-0 bg-[#0c0c0e] z-10 shadow-sm">
                        <tr className="border-b border-white/5">
                            <th className="px-4 py-2 text-zinc-500 font-medium">Address</th>
                            <th className="px-4 py-2 text-zinc-500 font-medium">Name</th>
                            <th className="px-4 py-2 text-zinc-500 font-medium">Signature</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((f, i) => (
                            <tr
                                key={i}
                                onClick={() => onSelectFunction?.(f)}
                                className={`border-b border-white/[0.02] hover:bg-white/[0.05] transition-colors cursor-pointer group`}
                            >
                                <td className="px-4 py-2 text-indigo-400 font-medium">{f.address}</td>
                                <td className="px-4 py-2 text-zinc-300 group-hover:text-white transition-colors">{f.name}</td>
                                <td className="px-4 py-2 text-zinc-500 italic max-w-md truncate">{f.signature}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {filtered.length === 0 && !loading && (
                    <div className="p-8 text-center text-zinc-600 italic">No symbols found</div>
                )}
            </div>
        </div>
    );
}
