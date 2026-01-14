'use client';
import { AlignLeft } from 'lucide-react';

interface DisassemblyViewProps {
    file: string | null;
    address?: string | null;
}

export default function DisassemblyView({ file }: DisassemblyViewProps) {
    return (
        <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 bg-[#0c0c0e]">
            <AlignLeft size={32} className="opacity-20 mb-2" />
            <span className="text-xs">Disassembly View</span>
            {file && <span className="text-[10px] font-mono mt-1 text-indigo-400">{file}</span>}
        </div>
    );
}
