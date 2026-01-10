'use client';

import { File, Trash2, Upload, Box, Code2, Layers, FolderKanban as FolderIcon, Activity, FolderOpen, Binary as BinaryIcon, ChevronRight, ChevronDown } from 'lucide-react';
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
    const [isRootOpen, setIsRootOpen] = useState(true);

    return (
        <div className="flex-1 bg-[#09090b] flex flex-col h-full select-none text-xs font-sans">
            {/* Toolbar */}
            <div className="h-8 flex items-center justify-between px-2 bg-[#2d2d30] border-b border-[#3e3e42]">
                <span className="font-semibold text-zinc-300">Project Manager</span>
                <div className="flex gap-1">
                    <button onClick={onUploadClick} className="text-zinc-400 hover:text-white p-1 hover:bg-white/10 rounded" title="Import File">
                        <Upload size={14} />
                    </button>
                </div>
            </div>

            {/* Tree Header / Columns */}
            <div className="flex items-center px-2 py-1 bg-[#252526] border-b border-[#3e3e42] text-[10px] text-zinc-500 font-bold uppercase tracking-wider">
                <div className="flex-1">Name</div>
                <div className="w-16">Type</div>
            </div>

            {/* Tree View */}
            <div className="flex-1 overflow-y-auto bg-[#1e1e1e]">
                {/* Root Folder */}
                <div className="flex flex-col">
                    <div
                        className="flex items-center px-2 py-1 hover:bg-[#2a2d2e] cursor-pointer text-zinc-300"
                        onClick={() => setIsRootOpen(!isRootOpen)}
                    >
                        {isRootOpen ? <ChevronDown size={12} className="mr-1 text-zinc-500" /> : <ChevronRight size={12} className="mr-1 text-zinc-500" />}
                        <FolderOpen size={14} className="mr-2 text-indigo-400" />
                        <span className="font-semibold">RE_BRAIN_PROJECT</span>
                    </div>

                    {isRootOpen && (
                        <div className="ml-4 border-l border-zinc-700/50 pl-1">
                            {files.length === 0 ? (
                                <div className="px-4 py-2 text-zinc-600 italic">No files in project</div>
                            ) : (
                                files.map(f => (
                                    <div
                                        key={f}
                                        onMouseEnter={() => setHoveredFile(f)}
                                        onMouseLeave={() => setHoveredFile(null)}
                                        onClick={() => setActiveFile(f)}
                                        className={`flex items-center px-2 py-0.5 cursor-pointer border border-transparent ${activeFile === f ? 'bg-[#094771] text-white border-[#007fd4]' : 'text-zinc-300 hover:bg-[#2a2d2e]'}`}
                                    >
                                        <div className="flex-1 flex items-center min-w-0">
                                            <BinaryIcon size={12} className={`mr-2 flex-shrink-0 ${activeFile === f ? 'text-sky-300' : 'text-emerald-500'}`} />
                                            <span className="truncate">{f}</span>
                                        </div>
                                        <div className="w-16 flex items-center justify-between text-zinc-500">
                                            <span className="text-[10px]">Binary</span>
                                            {hoveredFile === f && (
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); onDeleteFile(f); }}
                                                    className="text-zinc-500 hover:text-red-400 p-0.5 hover:bg-white/10 rounded"
                                                    title="Delete"
                                                >
                                                    <Trash2 size={12} />
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Bottom Panel (Scripting/Tools) */}
            <div className="h-1/3 border-t border-[#3e3e42] flex flex-col bg-[#1e1e1e]">
                <div className="px-2 py-1 bg-[#252526] border-b border-[#3e3e42] text-[10px] text-zinc-500 font-bold uppercase">
                    Tool Scripts
                </div>
                <div className="flex-1 overflow-auto p-1 space-y-0.5">
                    <div className="flex items-center gap-2 px-2 py-1 hover:bg-[#2a2d2e] cursor-pointer text-zinc-400 hover:text-indigo-300">
                        <Code2 size={12} />
                        <span>AnalyzeHeadless.java</span>
                    </div>
                    <div className="flex items-center gap-2 px-2 py-1 hover:bg-[#2a2d2e] cursor-pointer text-zinc-400 hover:text-indigo-300">
                        <Layers size={12} />
                        <span>ExportFunctions.py</span>
                    </div>
                </div>
            </div>

            {/* Status Bar */}
            <div className="h-6 bg-[#007acc] text-white flex items-center px-2 text-[10px]">
                <Box size={10} className="mr-1" />
                <span>ACTIVE PROJECT: RE_BRAIN</span>
                <span className="mx-2">|</span>
                <span>{files.length} ITEMS</span>
            </div>
        </div>
    );
}
