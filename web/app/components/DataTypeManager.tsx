'use client';
import { Database } from 'lucide-react';

interface DataTypeManagerProps {
    file: string | null;
}

export default function DataTypeManager({ file }: DataTypeManagerProps) {
    return (
        <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 bg-[#0c0c0e]">
            <Database size={32} className="opacity-20 mb-2" />
            <span className="text-xs">Data Type Manager</span>
            {file && <span className="text-[10px] font-mono mt-1 text-indigo-400">{file}</span>}
        </div>
    );
}
