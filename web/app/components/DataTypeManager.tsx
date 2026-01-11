'use client';

import { Database, RefreshCw, Folder, FileType, ChevronRight, ChevronDown } from 'lucide-react';
import { useState, useEffect } from 'react';

interface CategoryData {
    name: string;
    types: { name: string; size: number }[];
    subcategories: CategoryData[];
}

interface DataTypeManagerProps {
    file: string | null;
}

const CategoryNode = ({ category, depth = 0 }: { category: CategoryData, depth?: number }) => {
    const [isOpen, setIsOpen] = useState(depth === 0); // Open root by default

    return (
        <div style={{ paddingLeft: depth * 12 }}>
            <div
                className="flex items-center gap-1 py-0.5 hover:bg-white/5 rounded cursor-pointer group"
                onClick={() => setIsOpen(!isOpen)}
            >
                {(category.subcategories?.length || 0) > 0 || (category.types?.length || 0) > 0 ? (
                    isOpen ? <ChevronDown size={10} className="text-zinc-500" /> : <ChevronRight size={10} className="text-zinc-500" />
                ) : <div className="w-2.5" />}
                <Folder size={12} className={depth === 0 ? "text-indigo-400" : "text-yellow-600/70"} />
                <span className="text-zinc-300 text-xs font-medium truncate">{category.name}</span>
            </div>

            {isOpen && (
                <div className="flex flex-col">
                    {category.subcategories?.map((sub, i) => (
                        <CategoryNode key={i} category={sub} depth={depth + 1} />
                    ))}
                    {category.types?.map((type, i) => (
                        <div key={i} className="flex items-center gap-2 py-0.5 hover:bg-white/5 rounded cursor-default pl-4 group" style={{ marginLeft: depth * 12 }}>
                            <FileType size={10} className="text-zinc-600 group-hover:text-indigo-300 transition-colors" />
                            <span className="text-zinc-400 text-xs truncate flex-1">{type.name}</span>
                            <span className="text-[9px] text-zinc-600 mr-2">{type.size}b</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default function DataTypeManager({ file }: DataTypeManagerProps) {
    const [data, setData] = useState<CategoryData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchTypes = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`http://localhost:8005/binary/${file}/datatypes`);
            if (!res.ok) throw new Error("Failed to fetch datatypes");
            const jsonData = await res.json();
            if (jsonData.error) throw new Error(jsonData.error);
            setData(jsonData);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTypes();
    }, [file]);

    if (!file) {
        return (
            <div className="flex-1 overflow-auto p-4 flex flex-col items-center justify-center text-zinc-500">
                <Database size={32} className="opacity-20 mb-2" />
                <span className="text-xs">No active binary</span>
            </div>
        );
    }

    return (
        <div className="flex-1 bg-[#0c0c0e] text-zinc-300 font-mono text-sm overflow-auto p-2">
            <div className="flex items-center justify-between px-2 py-1 text-zinc-100 font-bold bg-white/5 rounded border border-white/5 mb-2">
                <div className="flex items-center gap-2">
                    <Database size={14} className="text-indigo-400" />
                    <span className="truncate max-w-[150px]">Data Types</span>
                </div>
                <button onClick={fetchTypes} className="text-zinc-500 hover:text-white" title="Refresh Types">
                    <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            {error && <div className="text-red-400 text-xs px-2 py-1">{error}</div>}

            {data && <CategoryNode category={data} />}
        </div>
    );
}
