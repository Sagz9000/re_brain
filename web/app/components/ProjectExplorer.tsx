'use client';

import { File, Trash2, Upload, Box, MoreVertical } from 'lucide-react';
import { useState } from 'react';

interface ProjectExplorerProps {
    files: string[];
    activeFile: string | null;
    setActiveFile: (file: string | null) => void;
    onUploadClick: () => void;
    onDeleteFile: (file: string) => void;
}

export default function ProjectExplorer({ files, activeFile, setActiveFile, onUploadClick, onDeleteFile }: ProjectExplorerProps) {
    const [hoveredFile, setHoveredFile] = useState<string | null>(null);

    return (
        <div className="w-64 bg-[#09090b] border-r border-white/5 flex flex-col h-full shrink-0 select-none">
            {/* Header */}
            <div className="h-10 flex items-center justify-between px-4 border-b border-white/5 bg-zinc-900/50">
                <span className="text-xs font-bold text-zinc-400 uppercase tracking-widest">Explorer</span>
                <button onClick={onUploadClick} className="text-zinc-400 hover:text-white transition-colors" title="Import Binary">
                    <Upload size={14} />
                </button>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto py-2">
                {files.length === 0 ? (
                    <div className="px-4 py-4 text-center">
                        <p className="text-xs text-zinc-500 mb-3">No Open Editors</p>
                        <button
                            onClick={onUploadClick}
                            className="bg-indigo-600/10 text-indigo-400 text-xs px-3 py-1.5 rounded hover:bg-indigo-600/20 transition-colors"
                        >
                            Import File
                        </button>
                    </div>
                ) : (
                    <div>
                        <div className="px-4 py-1 text-xs font-bold text-indigo-400 uppercase tracking-wider mb-1">
                            Binaries
                        </div>
                        {files.map(f => (
                            <div
                                key={f}
                                onMouseEnter={() => setHoveredFile(f)}
                                onMouseLeave={() => setHoveredFile(null)}
                                onClick={() => setActiveFile(f)}
                                className={`group flex items-center justify-between px-3 py-1 cursor-pointer border-l-2 transition-colors ${activeFile === f ? 'bg-white/5 border-indigo-500 text-zinc-100' : 'border-transparent text-zinc-400 hover:text-zinc-200 hover:bg-white/5'}`}
                            >
                                <div className="flex items-center gap-2 overflow-hidden">
                                    <File size={14} className={activeFile === f ? 'text-indigo-400' : 'text-zinc-500'} />
                                    <span className="text-sm truncate">{f}</span>
                                </div>
                                {hoveredFile === f && (
                                    <button
                                        onClick={(e) => { e.stopPropagation(); onDeleteFile(f); }}
                                        className="text-zinc-500 hover:text-red-400 p-1 rounded"
                                        title="Delete"
                                    >
                                        <Trash2 size={12} />
                                    </button>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Status Bar Section */}
            <div className="h-8 border-t border-white/5 flex items-center px-3 bg-[#0c0c0e]">
                <div className="flex items-center gap-1.5 text-zinc-500">
                    <Box size={12} />
                    <span className="text-[10px] font-mono">WORKSPACE</span>
                </div>
            </div>
        </div>
    );
}
