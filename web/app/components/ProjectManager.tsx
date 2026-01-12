'use client';

import { useState, useEffect } from 'react';
import { FolderTree, Trash2, RefreshCw, AlertTriangle } from 'lucide-react';
import { API_URL } from '../utils';

export default function ProjectManager() {
    const [projects, setProjects] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);
    const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);


    const fetchProjects = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/projects`);
            const data = await res.json();
            setProjects(data);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchProjects();
    }, []);

    const handleDelete = async (projectName: string) => {
        try {
            const res = await fetch(`${API_URL}/projects/${projectName}`, {
                method: 'DELETE'
            });
            const result = await res.json();

            if (result.error) {
                alert(`Error: ${result.error}`);
            } else {
                fetchProjects(); // Refresh list
            }
        } catch (e) {
            console.error(e);
            alert(`Failed to delete project: ${e}`);
        } finally {
            setDeleteConfirm(null);
        }
    };

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 flex flex-col">
            {/* Header */}
            <div className="h-10 border-b border-white/5 bg-[#121214] flex items-center px-4 justify-between">
                <div className="flex items-center gap-2">
                    <FolderTree size={14} className="text-indigo-400" />
                    <span className="text-xs font-bold text-zinc-300 uppercase tracking-widest">Project Manager</span>
                </div>
                <button onClick={fetchProjects} className="p-1.5 text-zinc-500 hover:text-white transition-colors">
                    <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            {/* Project List */}
            <div className="flex-1 overflow-auto p-4">
                {projects.length === 0 && !loading && (
                    <div className="text-center text-zinc-600 italic py-8">No projects found</div>
                )}

                <div className="space-y-2">
                    {projects.map((project) => (
                        <div key={project} className="bg-[#18181b] border border-white/5 rounded p-3 flex items-center justify-between group hover:border-indigo-500/30 transition-colors">
                            <div className="flex items-center gap-2">
                                <FolderTree size={16} className="text-zinc-500" />
                                <span className="text-sm font-mono text-zinc-300">{project}</span>
                            </div>

                            {deleteConfirm === project ? (
                                <div className="flex items-center gap-2">
                                    <span className="text-xs text-red-400 flex items-center gap-1">
                                        <AlertTriangle size={12} />
                                        Confirm?
                                    </span>
                                    <button
                                        onClick={() => handleDelete(project)}
                                        className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs hover:bg-red-500/40 transition-colors"
                                    >
                                        Yes, Delete
                                    </button>
                                    <button
                                        onClick={() => setDeleteConfirm(null)}
                                        className="px-2 py-1 bg-zinc-700/50 text-zinc-400 border border-white/10 rounded text-xs hover:bg-zinc-700 transition-colors"
                                    >
                                        Cancel
                                    </button>
                                </div>
                            ) : (
                                <button
                                    onClick={() => setDeleteConfirm(project)}
                                    className="opacity-0 group-hover:opacity-100 p-1.5 text-zinc-500 hover:text-red-400 transition-all"
                                    title="Delete project"
                                >
                                    <Trash2 size={14} />
                                </button>
                            )}
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
