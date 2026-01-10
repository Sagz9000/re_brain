'use client';

import { GitGraph, ZoomIn, ZoomOut, Move } from 'lucide-react';

export default function FunctionGraph() {
    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono relative overflow-hidden flex items-center justify-center">

            {/* Placeholder for SVG/Canvas Graph */}
            <div className="absolute inset-0 opacity-20 pointer-events-none">
                <svg width="100%" height="100%">
                    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                        <path d="M 40 0 L 0 0 0 40" fill="none" stroke="white" strokeWidth="0.5" />
                    </pattern>
                    <rect width="100%" height="100%" fill="url(#grid)" />
                </svg>
            </div>

            {/* Mock Nodes */}
            <div className="relative z-10 flex flex-col items-center gap-12">

                <div className="p-4 bg-zinc-900 border border-indigo-500/50 rounded shadow-xl flex flex-col gap-2 min-w-[200px]">
                    <div className="text-xs text-indigo-400 font-bold border-b border-indigo-500/20 pb-1 flex justify-between">
                        <span>entry_point</span>
                        <span>0x00401000</span>
                    </div>
                    <div className="text-[10px] text-zinc-400 font-mono">
                        <div>PUSH EBP</div>
                        <div>MOV EBP, ESP</div>
                        <div>SUB ESP, 0x40</div>
                    </div>
                </div>

                <div className="flex gap-16">
                    {/* True Branch */}
                    <div className="p-4 bg-zinc-900 border border-green-500/30 rounded shadow-xl flex flex-col gap-2 min-w-[180px] relative">
                        <div className="absolute -top-12 left-1/2 w-0.5 h-12 bg-green-500/50"></div>
                        <div className="text-xs text-green-400 font-bold border-b border-green-500/20 pb-1 flex justify-between">
                            <span>loc_401050</span>
                            <span>0x00401050</span>
                        </div>
                        <div className="text-[10px] text-zinc-400 font-mono">
                            <div>MOV EAX, 1</div>
                            <div>CALL 0x402010</div>
                        </div>
                    </div>

                    {/* False Branch */}
                    <div className="p-4 bg-zinc-900 border border-red-500/30 rounded shadow-xl flex flex-col gap-2 min-w-[180px] relative">
                        <div className="absolute -top-12 left-1/2 w-0.5 h-12 bg-red-500/50"></div>
                        <div className="text-xs text-red-400 font-bold border-b border-red-500/20 pb-1 flex justify-between">
                            <span>loc_401080</span>
                            <span>0x00401080</span>
                        </div>
                        <div className="text-[10px] text-zinc-400 font-mono">
                            <div>XOR EAX, EAX</div>
                            <div>JMP loc_401090</div>
                        </div>
                    </div>
                </div>

                <div className="p-4 bg-zinc-900 border border-zinc-700/50 rounded shadow-xl flex flex-col gap-2 min-w-[200px] relative">
                    {/* Connectors (Mock) */}
                    <div className="absolute -top-12 left-1/4 w-0.5 h-12 bg-zinc-700/50 -rotate-12 origin-bottom"></div>
                    <div className="absolute -top-12 right-1/4 w-0.5 h-12 bg-zinc-700/50 rotate-12 origin-bottom"></div>

                    <div className="text-xs text-zinc-400 font-bold border-b border-zinc-700/20 pb-1 flex justify-between">
                        <span>loc_401090</span>
                        <span>0x00401090</span>
                    </div>
                    <div className="text-[10px] text-zinc-400 font-mono opacity-70">
                        <div>MOV ESP, EBP</div>
                        <div>POP EBP</div>
                        <div>RET</div>
                    </div>
                </div>

            </div>

        </div>
    );
}
