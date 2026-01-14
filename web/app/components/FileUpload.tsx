'use client';

import { useState, useRef, useEffect } from 'react';
import { Upload, FileCode, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';
import { API_URL } from '../utils';

interface FileUploadProps {
    onUploadComplete: () => void;
    onClose?: () => void;
}

export default function FileUpload({ onUploadComplete }: FileUploadProps) {
    const [isDragging, setIsDragging] = useState(false);
    const [file, setFile] = useState<File | null>(null);
    const [projectName, setProjectName] = useState('');
    const [isNewProject, setIsNewProject] = useState(true);
    const [projects, setProjects] = useState<string[]>([]);
    const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
    const [errorMessage, setErrorMessage] = useState('');

    useEffect(() => {
        // Fetch existing projects
        fetch(`${API_URL}/projects`)
            .then(res => res.json())
            .then(data => setProjects(data))
            .catch(console.error);
    }, []);

    const handleDragOver = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(true);
    };

    const handleDragLeave = () => {
        setIsDragging(false);
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
        }
    };

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
        }
    };

    const handleSubmit = async () => {
        if (!file || (!projectName && isNewProject) || (!projectName && !isNewProject)) return;

        setStatus('uploading');
        const formData = new FormData();
        formData.append('file', file);
        formData.append('project_name', projectName);
        formData.append('is_new_project', isNewProject.toString());

        try {
            const res = await fetch(`${API_URL}/upload`, {
                method: 'POST',
                body: formData,
            });

            if (!res.ok) throw new Error('Upload failed');

            setStatus('success');
            onUploadComplete();
            setTimeout(() => {
                setStatus('idle');
                setFile(null);
                setProjectName('');
            }, 3000);
        } catch (e) {
            setStatus('error');
            setErrorMessage(e instanceof Error ? e.message : 'Unknown error');
        }
    };

    return (
        <div className="bg-[#0d0d10] border border-white/10 rounded-xl p-6 shadow-xl w-full max-w-md mx-auto relative overflow-hidden">
            <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                <Upload size={20} className="text-indigo-500" />
                Analyze Binary
            </h2>

            {/* Drop Zone */}
            <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`
                    border-2 border-dashed rounded-lg p-8 text-center transition-all duration-300
                    ${isDragging
                        ? 'border-indigo-500 bg-indigo-500/10'
                        : file
                            ? 'border-emerald-500/50 bg-emerald-500/5'
                            : 'border-white/10 hover:border-white/20 hover:bg-white/5'
                    }
                `}
            >
                <input
                    type="file"
                    onChange={handleFileSelect}
                    className="hidden"
                    id="file-upload"
                />

                {file ? (
                    <div className="flex flex-col items-center gap-2 text-emerald-400">
                        <FileCode size={32} />
                        <span className="font-mono text-xs">{file.name}</span>
                        <span className="text-[10px] text-zinc-500">{(file.size / 1024).toFixed(1)} KB</span>
                        <button
                            onClick={(e) => { e.stopPropagation(); setFile(null); }}
                            className="mt-2 text-[10px] text-red-400 hover:underline"
                        >
                            Remove
                        </button>
                    </div>
                ) : (
                    <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center gap-2 text-zinc-400">
                        <Upload size={32} className="opacity-50" />
                        <span className="text-sm">Drag binary here or click to browse</span>
                    </label>
                )}
            </div>

            {/* Project Settings */}
            <div className="mt-6 space-y-4">
                <div className="flex gap-4 text-sm">
                    <button
                        onClick={() => setIsNewProject(true)}
                        className={`flex-1 py-1.5 rounded-md border transition-colors ${isNewProject ? 'bg-indigo-600 border-indigo-500 text-white' : 'border-white/10 text-zinc-400 hover:text-zinc-200'}`}
                    >
                        New Project
                    </button>
                    <button
                        onClick={() => setIsNewProject(false)}
                        className={`flex-1 py-1.5 rounded-md border transition-colors ${!isNewProject ? 'bg-indigo-600 border-indigo-500 text-white' : 'border-white/10 text-zinc-400 hover:text-zinc-200'}`}
                    >
                        Existing
                    </button>
                </div>

                {isNewProject ? (
                    <input
                        type="text"
                        placeholder="Project Name"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="w-full bg-zinc-900/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50"
                    />
                ) : (
                    <select
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="w-full bg-zinc-900/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50"
                    >
                        <option value="">Select Project...</option>
                        {projects.map(p => (
                            <option key={p} value={p}>{p}</option>
                        ))}
                    </select>
                )}

                <button
                    onClick={handleSubmit}
                    disabled={!file || !projectName || status === 'uploading'}
                    className={`
                        w-full py-2.5 rounded-lg text-sm font-bold tracking-wide transition-all
                        ${status === 'success'
                            ? 'bg-emerald-600 text-white'
                            : status === 'error'
                                ? 'bg-red-600 text-white'
                                : 'bg-white text-black hover:bg-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed'
                        }
                    `}
                >
                    {status === 'uploading' ? (
                        <span className="flex items-center justify-center gap-2">
                            <Loader2 size={16} className="animate-spin" />
                            Ingesting...
                        </span>
                    ) : status === 'success' ? (
                        <span className="flex items-center justify-center gap-2">
                            <CheckCircle size={16} />
                            Ingestion Queued
                        </span>
                    ) : status === 'error' ? (
                        <span className="flex items-center justify-center gap-2">
                            <AlertCircle size={16} />
                            Failed
                        </span>
                    ) : (
                        'Analyze Binary'
                    )}
                </button>

                {status === 'error' && (
                    <p className="text-xs text-red-400 text-center">{errorMessage}</p>
                )}
            </div>
        </div>
    );
}
