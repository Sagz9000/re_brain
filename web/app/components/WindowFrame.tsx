'use client';

import React, { useState, useRef, useEffect, ReactNode } from 'react';
import { X, Maximize2, Minimize2, Move } from 'lucide-react';

interface WindowFrameProps {
    id: string;
    title: string;
    icon: any;
    children?: React.ReactNode;
    initialPos?: { x: number, y: number };
    initialSize?: { w: number, h: number };
    onClose: () => void;
    onFocus: () => void;
    zIndex: number;
    key?: string;
}

export default function WindowFrame({
    id, title, icon, children,
    initialPos = { x: 100, y: 100 },
    initialSize = { w: 600, h: 400 },
    onClose, onFocus, zIndex
}: WindowFrameProps) {
    const [pos, setPos] = useState(initialPos);
    const [size, setSize] = useState(initialSize);
    const [isDragging, setIsDragging] = useState(false);
    const [isResizing, setIsResizing] = useState(false);

    const frameRef = useRef<HTMLDivElement>(null);
    const dragOffset = useRef({ x: 0, y: 0 });

    useEffect(() => {
        const handleMouseMove = (e: MouseEvent) => {
            if (isDragging) {
                setPos({
                    x: e.clientX - dragOffset.current.x,
                    y: e.clientY - dragOffset.current.y
                });
            }
            if (isResizing && frameRef.current) {
                const rect = frameRef.current.getBoundingClientRect();
                setSize({
                    w: Math.max(300, e.clientX - rect.left),
                    h: Math.max(200, e.clientY - rect.top)
                });
            }
        };

        const handleMouseUp = () => {
            setIsDragging(false);
            setIsResizing(false);
        };

        if (isDragging || isResizing) {
            window.addEventListener('mousemove', handleMouseMove);
            window.addEventListener('mouseup', handleMouseUp);
        }

        return () => {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        };
    }, [isDragging, isResizing]);

    const startDrag = (e: React.MouseEvent) => {
        onFocus();
        const rect = frameRef.current?.getBoundingClientRect();
        if (rect) {
            dragOffset.current = {
                x: e.clientX - rect.left,
                y: e.clientY - rect.top
            };
            setIsDragging(true);
        }
    };

    return (
        <div
            ref={frameRef}
            onMouseDown={onFocus}
            style={{
                position: 'absolute',
                left: pos.x,
                top: pos.y,
                width: size.w,
                height: size.h,
                zIndex
            }}
            className="flex flex-col bg-[#0c0c0e]/90 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden shadow-2xl transition-shadow duration-300 ring-1 ring-white/5 active:ring-indigo-500/50"
        >
            {/* Header / Drag Handle */}
            <div
                onMouseDown={startDrag}
                className="h-9 fill-current bg-zinc-900/50 border-b border-white/5 flex items-center justify-between px-3 cursor-grab active:cursor-grabbing select-none"
            >
                <div className="flex items-center gap-2">
                    <div className="text-indigo-400 opacity-80">{icon}</div>
                    <span className="text-[11px] font-bold text-zinc-300 uppercase tracking-widest">{title}</span>
                </div>
                <div className="flex items-center gap-1">
                    <button onClick={onClose} className="p-1 hover:bg-red-500/20 hover:text-red-400 text-zinc-500 rounded-md transition-all">
                        <X size={14} />
                    </button>
                </div>
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-hidden relative flex flex-col">
                {children}
            </div>

            {/* Resize Handle */}
            <div
                onMouseDown={(e) => { e.stopPropagation(); setIsResizing(true); }}
                className="absolute bottom-0 right-0 w-4 h-4 cursor-nwse-resize flex items-end justify-end p-0.5"
            >
                <div className="w-1.5 h-1.5 border-r-2 border-b-2 border-zinc-600 rounded-sm" />
            </div>
        </div>
    );
}
