'use client';
import { ListTree } from 'lucide-react';

interface SymbolTreeProps {
    file: string | null;
    onSelectFunction?: (func: { name: string, address: string }) => void;
}

export default function SymbolTree({ file, onSelectFunction }: SymbolTreeProps) {
    return (
        <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 bg-[#0c0c0e]">
            <ListTree size={32} className="opacity-20 mb-2" />
            <span className="text-xs">Symbol Tree</span>
            {file && <span className="text-[10px] font-mono mt-1 text-indigo-400">{file}</span>}
        </div>
    );
}
