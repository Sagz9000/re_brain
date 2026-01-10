'use client';
import { GitCommit } from 'lucide-react';

interface CallTreeProps {
    file: string | null;
}

export default function CallTree({ file }: CallTreeProps) {
    return (
        <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 bg-[#0c0c0e]">
            <GitCommit size={32} className="opacity-20 mb-2" />
            <span className="text-xs">Function Call Tree</span>
            {file && <span className="text-[10px] font-mono mt-1 text-indigo-400">{file}</span>}
        </div>
    );
}
