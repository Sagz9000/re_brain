'use client';

import { Bookmark, RefreshCw, MessageSquare, Tag, Crosshair } from 'lucide-react';
import { useState, useEffect } from 'react';

interface BookmarkItem {
    address: string;
    type: string;
    category: string;
    comment: string;
}

interface BookmarkManagerProps {
    file: string | null;
    onSelectAddress?: (addr: string) => void;
}

export default function BookmarkManager({ file, onSelectAddress }: BookmarkManagerProps) {
    const [bookmarks, setBookmarks] = useState<BookmarkItem[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchBookmarks = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`http://localhost:8005/binary/${file}/bookmarks`);
            if (!res.ok) throw new Error("Failed to fetch bookmarks");
            const jsonData = await res.json();
            if (jsonData.error) throw new Error(jsonData.error);
            setBookmarks(jsonData);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchBookmarks();
    }, [file]);

    if (!file) {
        return (
            <div className="flex-1 overflow-auto p-4 flex flex-col items-center justify-center text-zinc-500">
                <Bookmark size={32} className="opacity-20 mb-2" />
                <span className="text-xs">No active binary</span>
            </div>
        );
    }

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono text-sm overflow-auto p-2">
            <div className="flex items-center justify-between px-2 py-1 text-zinc-100 font-bold bg-white/5 rounded border border-white/5 mb-2">
                <div className="flex items-center gap-2">
                    <Bookmark size={14} className="text-indigo-400" />
                    <span className="truncate max-w-[150px]">Bookmarks</span>
                </div>
                <button onClick={fetchBookmarks} className="text-zinc-500 hover:text-white" title="Refresh Bookmarks">
                    <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            {error && <div className="text-red-400 text-xs px-2 py-1">{error}</div>}

            {bookmarks.length === 0 && !loading && !error && (
                <div className="text-center text-zinc-600 text-xs py-4 italic">
                    No bookmarks found.
                </div>
            )}

            <div className="space-y-1">
                {bookmarks.map((bmk, i) => (
                    <div
                        key={i}
                        className="group flex flex-col gap-1 p-2 rounded hover:bg-white/5 cursor-pointer border border-transparent hover:border-white/5 transition-all"
                        onClick={() => onSelectAddress && onSelectAddress(bmk.address)}
                    >
                        <div className="flex items-center justify-between">
                            <span className="flex items-center gap-1.5 text-xs text-indigo-300 font-bold bg-indigo-500/10 px-1.5 py-0.5 rounded">
                                <Crosshair size={10} />
                                {bmk.address}
                            </span>
                            <span className="text-[10px] text-zinc-500 bg-zinc-800 px-1.5 rounded">{bmk.type}</span>
                        </div>

                        <div className="pl-1 flex items-start gap-2">
                            <Tag size={10} className="text-zinc-600 mt-0.5 shrink-0" />
                            <span className="text-[10px] text-zinc-400">{bmk.category}</span>
                        </div>

                        {bmk.comment && (
                            <div className="pl-1 flex items-start gap-2 mt-0.5">
                                <MessageSquare size={10} className="text-zinc-600 mt-0.5 shrink-0" />
                                <span className="text-[11px] text-zinc-300 italic leading-tight">{bmk.comment}</span>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}
