'use client';

import { FolderTree, MemoryStick, Box, FileCode, RefreshCw } from 'lucide-react';
import { useState, useEffect } from 'react';

interface MemoryBlock {
    name: string;
    start: string;
    end: string;
    size: string;
    perms: string;
    type: string;
}

interface ProgramTreeProps {
    file: string | null;
}

export default function ProgramTree({ file }: ProgramTreeProps) {
    const [blocks, setBlocks] = useState<MemoryBlock[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchTree = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`http://localhost:8005/binary/${file}/tree`);
            if (!res.ok) throw new Error("Failed to fetch tree");
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            setBlocks(data);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTree();
    }, [file]);

    if (!file) {
        return (
            <div className="flex-1 overflow-auto p-4 flex flex-col items-center justify-center text-zinc-500">
                <Box size={32} className="opacity-20 mb-2" />
                <span className="text-xs">No active binary</span>
            </div>
        );
    }

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono text-sm overflow-auto p-2">
            <div className="space-y-1">
                {/* Root: Program Image */}
                <div className="flex items-center justify-between px-2 py-1 text-zinc-100 font-bold bg-white/5 rounded border border-white/5">
                    <div className="flex items-center gap-2">
                        <Box size={14} className="text-indigo-400" />
                        <span className="truncate max-w-[150px]">{file}</span>
                    </div>
                    <button onClick={fetchTree} className="text-zinc-500 hover:text-white" title="Refresh Tree">
                        <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                    </button>
                </div>

                {/* Tree Structure */}
                <div className="pl-4 space-y-1 mt-2 border-l border-white/10 ml-2">
                    {/* Headers (Static for now) */}
                    <div className="flex items-center gap-2 px-2 py-0.5 hover:bg-white/5 rounded cursor-pointer text-zinc-400">
                        <FolderTree size={14} />
                        <span>Headers</span>
                    </div>

                    {/* Memory Blocks */}
                    <div className="flex items-center gap-2 px-2 py-0.5 hover:bg-white/5 rounded cursor-pointer text-zinc-400">
                        <MemoryStick size={14} />
                        <span>Memory Blocks</span>
                    </div>

                    {/* Sub-blocks (Dynamic) */}
                    <div className="pl-6 space-y-0.5 border-l border-white/10 ml-2">
                        {loading && <div className="text-xs text-zinc-500 italic px-2">Loading blocks...</div>}
                        {error && <div className="text-xs text-red-400 px-2">Error: {error}</div>}

                        {!loading && !error && blocks.map((block, i) => (
                            <div key={i} className="group flex items-center justify-between px-2 py-0.5 hover:bg-white/5 rounded cursor-pointer text-zinc-500 hover:text-indigo-300 transition-colors">
                                <span className="flex items-center gap-2 truncate">
                                    <FileCode size={12} className={block.perms.includes('X') ? 'text-red-400' : 'text-blue-400'} />
                                    {block.name}
                                </span>
                                <div className="flex items-center gap-2">
                                    <span className="text-[9px] text-zinc-600 bg-black/20 px-1 rounded">{block.perms}</span>
                                    <span className="text-[10px] opacity-50 font-mono">{block.start}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                    <div className="flex items-center gap-2 px-2 py-0.5 hover:bg-white/5 rounded cursor-pointer text-zinc-400">
                        <Box size={14} />
                        <span>Data Types</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
