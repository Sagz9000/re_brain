'use client';

import { useState, useEffect } from 'react';
import { FileType, Copy, RefreshCw, AlertCircle } from 'lucide-react';
import { API_URL } from '../utils';

interface DataTypeViewerProps {
    file: string;
    typeName: string;
    typePath?: string;
}

export default function DataTypeViewer({ file, typeName, typePath }: DataTypeViewerProps) {
    const [content, setContent] = useState<string>('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchPreview = async () => {
        if (!file || !typeName) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/datatype/preview`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type_name: typeName, category_path: typePath })
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            setContent(data.preview || '// No preview available');
        } catch (e: any) {
            setError(e.message || "Failed to fetch preview");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPreview();
    }, [file, typeName, typePath]);

    const copyToClipboard = () => {
        navigator.clipboard.writeText(content);
    };

    return (
        <div className="flex-1 flex flex-col min-h-0 bg-[#0c0c0e]">
            {/* Header */}
            <div className="h-10 border-b border-white/5 bg-[#121214] flex items-center justify-between px-4">
                <div className="flex items-center gap-3">
                    <FileType size={14} className="text-indigo-400" />
                    <span className="text-xs font-mono text-zinc-300">
                        {typeName} <span className="text-zinc-500">{typePath && typePath !== '/' ? `(${typePath})` : ''}</span>
                    </span>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={fetchPreview}
                        className="p-1.5 text-zinc-500 hover:text-white transition-colors"
                        title="Refresh"
                    >
                        <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                    </button>
                    <button
                        onClick={copyToClipboard}
                        className="p-1.5 text-zinc-500 hover:text-white transition-colors"
                        title="Copy Code"
                    >
                        <Copy size={14} />
                    </button>
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-4 font-mono text-sm relative">
                {loading ? (
                    <div className="absolute inset-0 flex items-center justify-center bg-black/20 backdrop-blur-sm z-10">
                        <div className="text-center">
                            <RefreshCw size={24} className="animate-spin text-indigo-500 mx-auto mb-2" />
                            <p className="text-xs text-zinc-500">Generating Preview...</p>
                        </div>
                    </div>
                ) : error ? (
                    <div className="flex flex-col items-center justify-center h-full text-zinc-500 gap-3">
                        <AlertCircle size={32} className="text-red-500/50" />
                        <div className="text-center max-w-md">
                            <p className="text-zinc-300 mb-1">Preview Error</p>
                            <p className="text-xs opacity-50">{error}</p>
                        </div>
                    </div>
                ) : (
                    <pre className="text-zinc-300 leading-relaxed tab-size-4 selection:bg-indigo-500/30">
                        {content}
                    </pre>
                )}
            </div>
        </div>
    );
}
