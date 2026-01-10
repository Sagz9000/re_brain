'use client';

import { FolderTree, MemoryStick, Box, FileCode, RefreshCw } from 'lucide-react';
import { useState, useEffect } from 'react';

interface TreeData {
    blocks: MemoryBlock[];
    headers: { address: string; type: string; value: string }[];
    datatypes: string[];
}

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
    const [data, setData] = useState<TreeData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [expanded, setExpanded] = useState({ blocks: true, headers: false, types: false });

    const fetchTree = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`http://localhost:8005/binary/${file}/tree`);
            if (!res.ok) throw new Error("Failed to fetch tree");
            const jsonData = await res.json();
            if (jsonData.error) throw new Error(jsonData.error);
            // Handle legacy format (array) vs new format (object)
            if (Array.isArray(jsonData)) {
                setData({ blocks: jsonData, headers: [], datatypes: [] });
            } else {
                setData(jsonData);
            }
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTree();
    }, [file]);

    const toggle = (section: keyof typeof expanded) => {
        setExpanded(prev => ({ ...prev, [section]: !prev[section] }));
    };

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
                <div className="flex items-center justify-between px-2 py-1 text-zinc-100 font-bold bg-white/5 rounded border border-white/5 mb-2">
                    <div className="flex items-center gap-2">
                        <Box size={14} className="text-indigo-400" />
                        <span className="truncate max-w-[150px]">{file}</span>
                    </div>
                    <button onClick={fetchTree} className="text-zinc-500 hover:text-white" title="Refresh Tree">
                        <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                    </button>
                </div>

                {error && <div className="text-red-400 text-xs px-2 py-1">{error}</div>}

                {/* Headers Section */}
                <div>
                    <div
                        className="flex items-center gap-2 px-2 py-1 hover:bg-white/5 rounded cursor-pointer text-zinc-400 hover:text-zinc-200"
                        onClick={() => toggle('headers')}
                    >
                        <FileCode size={12} />
                        <span className="text-xs font-bold uppercase tracking-wider">Headers & Identifiers</span>
                        <span className="text-[10px] text-zinc-600 ml-auto">{data?.headers?.length || 0}</span>
                    </div>
                    {expanded.headers && data?.headers && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-1">
                            {data.headers.map((h, i) => (
                                <div key={i} className="text-[10px] flex gap-2">
                                    <span className="text-emerald-500/80">{h.address}</span>
                                    <span className="text-indigo-400">{h.type}</span>
                                    <span className="text-zinc-500 truncate max-w-[100px]">{h.value}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Memory Blocks Section */}
                <div>
                    <div
                        className="flex items-center gap-2 px-2 py-1 hover:bg-white/5 rounded cursor-pointer text-zinc-400 hover:text-zinc-200"
                        onClick={() => toggle('blocks')}
                    >
                        <MemoryStick size={12} />
                        <span className="text-xs font-bold uppercase tracking-wider">Memory Blocks</span>
                        <span className="text-[10px] text-zinc-600 ml-auto">{data?.blocks?.length || 0}</span>
                    </div>

                    {expanded.blocks && data?.blocks && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-1">
                            {data.blocks.map((block, i) => (
                                <div key={i} className="group relative">
                                    <div className="flex items-center gap-2 text-xs">
                                        <FolderTree size={10} className="text-yellow-600/70" />
                                        <span className="text-zinc-300">{block.name}</span>
                                        <span className={`text-[10px] px-1 rounded ${block.perms.includes('X') ? 'bg-red-500/20 text-red-400' : 'bg-zinc-800 text-zinc-500'}`}>
                                            {block.perms || '---'}
                                        </span>
                                    </div>
                                    <div className="pl-5 text-[10px] text-zinc-600 font-normal">
                                        {block.start} - {block.end} ({parseInt(block.size).toLocaleString()} bytes)
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Data Types Section */}
                <div>
                    <div
                        className="flex items-center gap-2 px-2 py-1 hover:bg-white/5 rounded cursor-pointer text-zinc-400 hover:text-zinc-200"
                        onClick={() => toggle('types')}
                    >
                        <FolderTree size={12} />
                        <span className="text-xs font-bold uppercase tracking-wider">Data Types</span>
                        <span className="text-[10px] text-zinc-600 ml-auto">{data?.datatypes?.length || 0}</span>
                    </div>
                    {expanded.types && data?.datatypes && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-2 py-1 space-y-0.5">
                            {data.datatypes.map((t, i) => (
                                <div key={i} className="text-[10px] text-zinc-500 hover:text-indigo-300 cursor-pointer">
                                    {t}
                                </div>
                            ))}
                        </div>
                    )}
                </div>

            </div>
        </div>
    );
}
