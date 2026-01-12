'use client';

import { useState, useEffect } from 'react';
import { ArrowLeft, ArrowRight, Save } from 'lucide-react';
import { API_URL } from '../utils';

interface HexViewerProps {
    file: string;
    address?: string | null;
}

export default function HexViewer({ file, address }: HexViewerProps) {
    const [hexData, setHexData] = useState<string>('');
    const [offset, setOffset] = useState(0);
    const [limit] = useState(512); // bytes per page
    const [totalSize, setTotalSize] = useState(0);
    const [loading, setLoading] = useState(false);


    // sync address prop to offset
    useEffect(() => {
        if (address) {
            let addr = address;
            if (addr.startsWith('0x')) addr = addr.slice(2);
            const num = parseInt(addr, 16);
            if (!isNaN(num)) {
                setOffset(num);
            }
        }
    }, [address]);

    useEffect(() => {
        const fetchHex = async () => {
            setLoading(true);
            try {
                const res = await fetch(`${API_URL}/binary/${file}/hex?offset=${offset}&limit=${limit}`);
                const data = await res.json();
                if (data.hex) {
                    setHexData(data.hex);
                    setTotalSize(data.total_size);
                }
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        };
        fetchHex();
    }, [file, offset, limit]);

    // Render helper
    const renderHexGrid = () => {
        const bytes = hexData.match(/.{1,2}/g) || [];
        const rows = [];
        const bytesPerRow = 16;

        for (let i = 0; i < bytes.length; i += bytesPerRow) {
            const chunk = bytes.slice(i, i + bytesPerRow);
            const rowOffset = (offset + i).toString(16).padStart(8, '0').toUpperCase();

            // Hex part
            const hexString = chunk.map((b, idx) => (
                <span key={idx} className={`inline-block w-6 text-center ${b === '00' ? 'text-zinc-700' : 'text-zinc-300'}`}>
                    {b.toUpperCase()}
                </span>
            ));

            // Ascii part
            const asciiString = chunk.map(b => {
                const code = parseInt(b, 16);
                const char = (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
                return char;
            }).join('');

            rows.push(
                <div key={i} className="flex font-mono text-sm hover:bg-white/5 px-2 rounded">
                    <span className="text-zinc-500 mr-4 select-none">{rowOffset}</span>
                    <div className="flex gap-1 mr-4 border-r border-white/5 pr-4 select-text">
                        {chunk.map((b, idx) => (
                            <span key={idx} className={`inline-block w-6 text-center ${b === '00' ? 'text-zinc-600' : 'text-zinc-300'}`}>
                                {b.toUpperCase()}
                            </span>
                        ))}
                    </div>
                    <span className="text-zinc-400 opacity-60 tracking-widest">{asciiString}</span>
                </div>
            );
        }
        return rows;
    };

    return (
        <div className="flex-1 flex flex-col h-full overflow-hidden">
            {/* Toolbar */}
            <div className="h-12 border-b border-white/5 flex items-center justify-between px-4 bg-zinc-900/30">
                <div className="flex items-center gap-4">
                    <span className="font-mono text-xs text-zinc-400">OFFSET: 0x{offset.toString(16).toUpperCase()}</span>
                    <div className="h-4 w-px bg-white/10" />
                    <span className="font-mono text-xs text-zinc-400">SIZE: {totalSize.toLocaleString()} bytes</span>
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={() => setOffset(Math.max(0, offset - limit))}
                        disabled={offset === 0}
                        className="p-1.5 hover:bg-white/10 rounded disabled:opacity-30"
                    >
                        <ArrowLeft size={16} />
                    </button>
                    <button
                        onClick={() => setOffset(offset + limit)}
                        disabled={offset + limit >= totalSize}
                        className="p-1.5 hover:bg-white/10 rounded disabled:opacity-30"
                    >
                        <ArrowRight size={16} />
                    </button>
                </div>
            </div>

            {/* Grid */}
            <div className="flex-1 overflow-auto p-4 scrollbar-thin scrollbar-thumb-zinc-800">
                {loading ? (
                    <div className="text-zinc-500 p-10 font-mono">Loading Data...</div>
                ) : (
                    <div className="space-y-0.5">
                        {renderHexGrid()}
                    </div>
                )}
            </div>
        </div>
    );
}
