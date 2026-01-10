'use client';
import { Play } from 'lucide-react';

export default function ScriptManager() {
    return (
        <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 bg-[#0c0c0e]">
            <Play size={32} className="opacity-20 mb-2" />
            <span className="text-xs">Script Manager</span>
        </div>
    );
}
