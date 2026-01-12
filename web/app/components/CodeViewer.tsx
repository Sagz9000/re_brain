'use client';

import { useState, useEffect } from 'react';
import { Code, Copy, RefreshCw, AlertCircle, MessageSquare } from 'lucide-react';
import { API_URL } from '../utils';


interface CodeViewerProps {
    file: string;
    address: string;
    functionName: string;
}

export default function CodeViewer({ file, address, functionName }: CodeViewerProps) {
    const [code, setCode] = useState<string>('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchDecompilation = async () => {
        if (!file || !address) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/function/${address}/decompile`);
            const data = await res.json();
            if (data.error) setError(data.error);
            else setCode(data.code || '');
        } catch (e) {
            setError("Failed to reach decomposition server.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDecompilation();
    }, [file, address]);

    const copyToClipboard = () => {
        navigator.clipboard.writeText(code);
    };

    const handleAddComment = async () => {
        const text = window.prompt(`Add EOL comment at ${address}:`);
        if (!text) return;

        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/binary/${file}/comment`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    address: address,
                    text: text,
                    comment_type: 'eol' // Default to EOL for simplicity
                })
            });
            const result = await res.json();
            if (result.status === 'success') {
                fetchDecompilation();
            } else {
                alert(`Failed to add comment: ${result.error || 'Unknown error'}`);
            }
        } catch (e) {
            alert(`Failed to add comment: ${e}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex-1 flex flex-col min-h-0 bg-[#0c0c0e]">
            {/* Header */}
            <div className="h-10 border-b border-white/5 bg-[#121214] flex items-center justify-between px-4">
                <div className="flex items-center gap-3">
                    <Code size={14} className="text-indigo-400" />
                    <span className="text-xs font-mono text-zinc-300">
                        {functionName} <span className="text-zinc-500">@ {address}</span>
                    </span>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={fetchDecompilation}
                        className="p-1.5 text-zinc-500 hover:text-white transition-colors"
                        title="Refresh"
                    >
                        <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                    </button>
                    <button
                        onClick={handleAddComment}
                        className="p-1.5 text-zinc-500 hover:text-white transition-colors"
                        title="Add EOL Comment"
                    >
                        <MessageSquare size={14} />
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
                    <div className="absolute inset-0 flex items-center justify-center bg-black/20 backdrop-blur-sm z-10 transition-opacity">
                        <div className="text-center">
                            <RefreshCw size={24} className="animate-spin text-indigo-500 mx-auto mb-2" />
                            <p className="text-xs text-zinc-500">Decompiling via Ghidra...</p>
                        </div>
                    </div>
                ) : error ? (
                    <div className="flex flex-col items-center justify-center h-full text-zinc-500 gap-3">
                        <AlertCircle size={32} className="text-red-500/50" />
                        <div className="text-center max-w-md">
                            <p className="text-zinc-300 mb-1">Decompilation Error</p>
                            <p className="text-xs opacity-50">{error}</p>
                        </div>
                    </div>
                ) : (
                    <pre className="text-zinc-300 leading-relaxed tab-size-4 selection:bg-indigo-500/30">
                        {code || "// No code available"}
                    </pre>
                )}
            </div>

            {/* Status Footer */}
            <div className="h-6 border-t border-white/5 bg-[#09090b] flex items-center px-3 justify-between">
                <span className="text-[10px] text-zinc-600 font-mono uppercase tracking-widest">re-Brain-Decompiler-v1</span>
                {code && (
                    <span className="text-[10px] text-indigo-400/50 font-mono italic">
                        {code.split('\n').length} lines generated
                    </span>
                )}
            </div>
        </div>
    );
}
