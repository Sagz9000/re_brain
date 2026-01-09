'use client';

import { Binary, Box, FileCode, HardDrive } from 'lucide-react';

interface SidebarProps {
    activeView: 'dashboard' | 'hex' | 'functions';
    setActiveView: (view: 'dashboard' | 'hex' | 'functions') => void;
    files: string[];
    activeFile: string | null;
    setActiveFile: (file: string) => void;
}

export default function Sidebar({ activeView, setActiveView, files, activeFile, setActiveFile }: SidebarProps) {
    return (
        <div className="w-64 bg-[#09090b] border-r border-white/5 flex flex-col h-full shrink-0">
            {/* Logo */}
            <div className="h-16 flex items-center px-6 border-b border-white/5">
                <Box className="text-indigo-500 mr-2" size={20} />
                <span className="font-bold text-zinc-100">re-Brain</span>
            </div>

            {/* Navigation */}
            <div className="p-4 space-y-6">

                {/* Views */}
                <div>
                    <div className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-3 px-2">Analysis Tools</div>
                    <div className="space-y-1">
                        <button
                            onClick={() => setActiveView('dashboard')}
                            className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${activeView === 'dashboard' ? 'bg-indigo-500/10 text-indigo-400' : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-200'}`}
                        >
                            <HardDrive size={16} />
                            Dashboard
                        </button>
                        <button
                            onClick={() => setActiveView('functions')}
                            disabled={!activeFile}
                            className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${activeView === 'functions' ? 'bg-indigo-500/10 text-indigo-400' : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed'}`}
                        >
                            <FileCode size={16} />
                            Function Inspector
                        </button>
                        <button
                            onClick={() => setActiveView('hex')}
                            disabled={!activeFile}
                            className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${activeView === 'hex' ? 'bg-indigo-500/10 text-indigo-400' : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed'}`}
                        >
                            <Binary size={16} />
                            Hex Viewer
                        </button>
                    </div>
                </div>

                {/* Files */}
                <div>
                    <div className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-3 px-2">Workspace Files</div>
                    <div className="space-y-1">
                        {files.length === 0 ? (
                            <div className="px-3 py-2 text-sm text-zinc-600 italic">No files loaded</div>
                        ) : (
                            files.map(f => (
                                <button
                                    key={f}
                                    onClick={() => setActiveFile(f)}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors truncate ${activeFile === f ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:bg-white/5'}`}
                                >
                                    <span className="truncate">{f}</span>
                                </button>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
