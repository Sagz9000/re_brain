'use client';

import { Cpu, Shield, Activity, Power } from 'lucide-react';

interface HeaderProps {
    apiStatus: 'online' | 'offline' | 'checking';
    onFeatureClick: (feature: string) => void;
}

export default function Header({ apiStatus, onFeatureClick }: HeaderProps) {
    return (
        <header className="h-16 border-b border-white/5 bg-zinc-950/80 backdrop-blur-xl flex items-center justify-between px-6 z-50 fixed top-0 w-full shadow-2xl shadow-black/50">
            <div className="flex items-center gap-4">
                <div className="relative group cursor-pointer overflow-hidden rounded-xl">
                    <div className="absolute inset-0 bg-gradient-to-br from-indigo-600 to-purple-700 opacity-80 group-hover:opacity-100 transition-opacity duration-500" />
                    <div className="relative w-10 h-10 flex items-center justify-center bg-black/20 backdrop-blur-sm">
                        <Cpu size={20} className="text-white drop-shadow-md" />
                    </div>
                </div>
                <div>
                    <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                        re-Brain
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            BETA
                        </span>
                    </h1>
                    <p className="text-[10px] text-zinc-500 font-medium tracking-wide uppercase">Rate-Monitored Engineering Environment</p>
                </div>
            </div>

            <div className="flex items-center gap-4">
                {/* Status Indicator */}
                <div className={`
                    flex items-center gap-2 px-3 py-1.5 border rounded-full transition-all duration-500
                    ${apiStatus === 'online'
                        ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400 shadow-[0_0_15px_-3px_rgba(16,185,129,0.2)]'
                        : apiStatus === 'offline'
                            ? 'bg-red-500/5 border-red-500/20 text-red-400'
                            : 'bg-amber-500/5 border-amber-500/20 text-amber-400'
                    }
                `}>
                    <div className="relative flex h-2 w-2">
                        {apiStatus === 'online' && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                        <span className={`relative inline-flex rounded-full h-2 w-2 ${apiStatus === 'online' ? 'bg-emerald-500' : apiStatus === 'offline' ? 'bg-red-500' : 'bg-amber-500'}`}></span>
                    </div>
                    <span className="text-[10px] font-bold tracking-widest uppercase">
                        {apiStatus === 'online' ? 'System Operational' : apiStatus === 'offline' ? 'System Disconnected' : 'Connecting...'}
                    </span>
                </div>

                <div className="h-6 w-px bg-white/10 mx-2" />

                <button
                    onClick={() => onFeatureClick('Upload')} // Trigger Upload Modal
                    className="p-2 text-zinc-400 hover:text-white hover:bg-white/5 rounded-lg transition-all duration-300 group relative"
                    title="Upload Binary"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="group-hover:-translate-y-1 transition-transform">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="17 8 12 3 7 8" />
                        <line x1="12" y1="3" x2="12" y2="15" />
                    </svg>
                </button>

                <button
                    onClick={() => onFeatureClick('Shield')}
                    className="p-2 text-zinc-400 hover:text-white hover:bg-white/5 rounded-lg transition-all duration-300 group relative"
                >
                    <Shield size={18} className="group-hover:scale-110 transition-transform" />
                    <span className="absolute -bottom-8 left-1/2 -translate-x-1/2 px-2 py-1 bg-zinc-900 border border-white/10 rounded text-[10px] text-zinc-300 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none">
                        Security Status
                    </span>
                </button>
            </div>
        </header>
    );
}
