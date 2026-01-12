'use client';

import { useState, useEffect } from 'react';
import { GitGraph, ZoomIn, ZoomOut, Move, ArrowRight } from 'lucide-react';
import { API_URL } from '../utils';

interface FunctionGraphProps {
    file: string | null;
    functionAddress: string | null;
}

interface Block {
    id: string;
    start: string;
    end: string;
    instructions: string[];
}

interface Edge {
    from: string;
    to: string;
    type: string;
}

interface CFGData {
    name: string;
    entry: string;
    blocks: Block[];
    edges: Edge[];
}

export default function FunctionGraph({ file, functionAddress }: FunctionGraphProps) {
    const [data, setData] = useState<CFGData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);


    useEffect(() => {
        if (!file || !functionAddress) {
            setData(null);
            return;
        }

        const fetchCFG = async () => {
            setLoading(true);
            setError(null);
            try {
                // Encode address if needed, though usually hex string is safe
                const res = await fetch(`${API_URL}/binary/${file}/function/${functionAddress}/cfg`);
                const json = await res.json();

                if (json.error) {
                    setError(json.error);
                } else {
                    setData(json);
                }
            } catch (e) {
                console.error(e);
                setError("Failed to fetch graph data");
            } finally {
                setLoading(false);
            }
        };

        fetchCFG();
    }, [file, functionAddress]);

    // Simple layout: just stack blocks for now, but in a real app use a graph library
    // We will try to map edges visually if possible, or just list blocks with jump targets

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono relative overflow-hidden flex flex-col">

            {/* Status Bar */}
            <div className="h-8 border-b border-white/5 bg-[#121214] flex items-center px-4 justify-between">
                <div className="text-xs text-zinc-500">
                    {file && functionAddress ? (
                        <span>Graph: <span className="text-zinc-300">{functionAddress}</span></span>
                    ) : (
                        <span>No function selected</span>
                    )}
                </div>
                {loading && <span className="text-xs text-indigo-400 animate-pulse">Generated Graph...</span>}
            </div>

            {/* Canvas / Container */}
            <div className="flex-1 overflow-auto p-8 relative">

                {/* Background Grid */}
                <div className="absolute inset-0 opacity-10 pointer-events-none">
                    <svg width="100%" height="100%">
                        <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="white" strokeWidth="0.5" />
                        </pattern>
                        <rect width="100%" height="100%" fill="url(#grid)" />
                    </svg>
                </div>

                {error ? (
                    <div className="flex items-center justify-center h-full text-red-400 text-sm">
                        {error}
                    </div>
                ) : !data ? (
                    <div className="flex items-center justify-center h-full text-zinc-600 text-sm italic">
                        Select a function to view its Control Flow Graph
                    </div>
                ) : (
                    <div className="relative z-10 flex flex-col items-center gap-8 pb-20">
                        {/* Render Blocks Simply Stacked (TODO: integrate proper layout engine like dagre) */}
                        {data.blocks.map((block) => (
                            <div key={block.id} className="p-0 bg-zinc-900 border border-zinc-700/50 rounded shadow-xl flex flex-col min-w-[300px] max-w-xl group hover:border-indigo-500/50 transition-colors">
                                <div className="bg-[#18181b] px-3 py-1.5 border-b border-white/5 flex justify-between items-center">
                                    <span className="text-xs font-bold text-indigo-400">{block.id}</span>
                                    <span className="text-[10px] text-zinc-500 font-mono">{block.start}</span>
                                </div>
                                <div className="p-3 bg-[#0c0c0e]/50 text-[11px] font-mono text-zinc-400 space-y-0.5">
                                    {block.instructions.map((inst, idx) => (
                                        <div key={idx} className="hover:bg-white/5 px-1 rounded flex gap-4">
                                            <span className="text-indigo-300 w-12 shrink-0">{inst.split(" ")[0]}</span>
                                            <span className="text-zinc-400">{inst.split(" ").slice(1).join(" ")}</span>
                                        </div>
                                    ))}
                                </div>
                                {/* Outgoing Edges Info */}
                                <div className="px-3 py-1.5 border-t border-white/5 bg-[#18181b]/50 flex gap-2 justify-end">
                                    {data.edges.filter(e => e.from === block.id).map((edge, i) => (
                                        <div key={i} className="flex items-center gap-1 text-[10px]">
                                            <span className={`uppercase font-bold ${edge.type.includes("CONDITIONAL") ? (edge.type.includes("FALL") ? "text-red-400" : "text-green-400") : "text-zinc-500"}`}>
                                                {edge.type.replace("FLOW", "")}
                                            </span>
                                            <ArrowRight size={10} className="text-zinc-600" />
                                            <span className="text-zinc-300 font-mono">{edge.to}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
