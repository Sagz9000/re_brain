'use client';

import { Terminal, RefreshCw, Maximize2 } from 'lucide-react';
import { useRef } from 'react';

export default function GhidraPanel() {
    const frameRef = useRef<HTMLIFrameElement>(null);

    const reloadVNC = () => {
        if (frameRef.current) {
            frameRef.current.src = frameRef.current.src;
        }
    };

    return (
        <div className="flex-[3] relative group border-r border-white/5 bg-[#0a0a0c] overflow-hidden flex flex-col">
            {/* Controls Overlay */}
            <div className="absolute top-0 left-0 right-0 h-14 bg-gradient-to-b from-black/80 to-transparent z-10 pointer-events-none" />

            {/* Controls */}
            <div className="absolute top-4 left-4 z-20 flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-all duration-300 translate-y-2 group-hover:translate-y-0">
                <div className="px-3 py-1.5 bg-black/60 backdrop-blur-md border border-white/10 rounded-lg flex items-center gap-2 text-xs font-medium text-zinc-300 shadow-xl">
                    <Terminal size={14} className="text-indigo-400" />
                    <span>Ghidra VNC</span>
                </div>
                <button
                    onClick={reloadVNC}
                    className="p-1.5 bg-zinc-900/80 hover:bg-indigo-600/80 backdrop-blur-md border border-white/10 rounded-lg text-zinc-400 hover:text-white transition-all shadow-xl"
                    title="Reload VNC"
                >
                    <RefreshCw size={14} />
                </button>
                <button
                    onClick={() => window.open('http://localhost:6080/vnc.html?autoconnect=true&resize=scale&password=ghidra', '_blank', 'width=1920,height=1080')}
                    className="p-1.5 bg-zinc-900/80 hover:bg-indigo-600/80 backdrop-blur-md border border-white/10 rounded-lg text-zinc-400 hover:text-white transition-all shadow-xl"
                    title="Pop-out Window"
                >
                    <Maximize2 size={14} />
                </button>
            </div>

            {/* VNC Frame */}
            <iframe
                ref={frameRef}
                src="http://localhost:6080/vnc.html?autoconnect=true&resize=scale&password=ghidra"
                className="w-full h-full border-none bg-[#0a0a0c]"
                title="Ghidra Workspace"
            />

            {/* Loading/Error State Placeholder (Behind Iframe usually, but useful if iframe fails) */}
            <div className="absolute inset-0 flex items-center justify-center -z-10">
                <div className="text-center">
                    <div className="w-8 h-8 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mx-auto mb-4" />
                    <p className="text-xs text-zinc-500 font-mono">Initializing Graphical Environment...</p>
                </div>
            </div>
        </div>
    );
}
