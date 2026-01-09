'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Layers, BookOpen, Shield, Sparkles, AlertCircle } from 'lucide-react';

interface ChatPanelProps {
    apiStatus: 'online' | 'offline' | 'checking';
    onApiStatusChange: (status: 'online' | 'offline' | 'checking') => void;
}

interface Message {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export default function ChatPanel({ apiStatus, onApiStatusChange }: ChatPanelProps) {
    const [messages, setMessages] = useState<Message[]>([
        { role: 'assistant', content: "Hello! I'm re-Brain. Upload a binary or ask me anything about your current analysis context." }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const chatEndRef = useRef<HTMLDivElement>(null);

    const API_URL = 'http://localhost:8005';

    const scrollToBottom = () => {
        chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages, isTyping]);

    // Initial Health Check
    useEffect(() => {
        const checkHealth = async () => {
            try {
                const res = await fetch(`${API_URL}/health`);
                if (res.ok) {
                    onApiStatusChange('online');
                } else {
                    onApiStatusChange('offline');
                }
            } catch (e) {
                onApiStatusChange('offline');
            }
        };

        checkHealth();
        // Poll every 30s
        const interval = setInterval(checkHealth, 30000);
        return () => clearInterval(interval);
    }, [onApiStatusChange]);

    const handleSend = async () => {
        if (!input.trim()) return;

        const userMessage = { role: 'user', content: input } as Message;
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsTyping(true);

        try {
            const response = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: input }),
            });

            if (!response.ok) throw new Error(response.statusText);

            const data = await response.json();
            setMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
        } catch (error) {
            setMessages(prev => [...prev, { role: 'assistant', content: `Connection Failed: ${error}` }]);
            onApiStatusChange('offline');
        } finally {
            setIsTyping(false);
        }
    };

    return (
        <div className="flex-1 max-w-[450px] flex flex-col bg-[#0d0d10] border-l border-white/5 relative z-30 shadow-2xl">
            {/* Header */}
            <div className="h-14 border-b border-white/5 flex items-center justify-between px-6 bg-[#0d0d10]/95 backdrop-blur">
                <div className="flex items-center gap-2 text-xs font-bold text-zinc-400 uppercase tracking-widest">
                    <Layers size={14} className="text-indigo-500" />
                    Intelligence Stream
                </div>
                <div className="flex gap-2">
                    <div className="p-1.5 hover:bg-white/5 rounded-md cursor-pointer transition-colors group" title="Knowledge Base: Active">
                        <BookOpen size={14} className="text-zinc-600 group-hover:text-blue-400 transition-colors" />
                    </div>
                </div>
            </div>

            {/* Chat Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-6 scrollbar-thin scrollbar-thumb-zinc-800 scrollbar-track-transparent">
                {messages.map((m, i) => (
                    <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div className={`
                            max-w-[85%] px-5 py-3 rounded-2xl text-sm leading-relaxed shadow-sm
                            ${m.role === 'user'
                                ? 'bg-indigo-600 text-white rounded-tr-none'
                                : m.role === 'system'
                                    ? 'bg-zinc-900/50 border border-white/5 text-zinc-500 text-xs font-mono py-2'
                                    : 'bg-zinc-800/40 border border-white/5 text-zinc-200 rounded-tl-none'
                            }
                        `}>
                            {m.role === 'assistant' && (
                                <div className="flex items-center gap-2 mb-2 text-[10px] font-bold text-indigo-400 uppercase tracking-wider">
                                    <Sparkles size={10} />
                                    AI Analyst
                                </div>
                            )}
                            {m.content}
                        </div>
                    </div>
                ))}

                {isTyping && (
                    <div className="flex justify-start">
                        <div className="bg-zinc-800/40 border border-white/5 px-4 py-3 rounded-2xl rounded-tl-none flex gap-1.5 items-center">
                            <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce" />
                            <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce [animation-delay:0.2s]" />
                            <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce [animation-delay:0.4s]" />
                        </div>
                    </div>
                )}
                {apiStatus === 'offline' && (
                    <div className="flex justify-center">
                        <div className="flex items-center gap-2 px-3 py-1 bg-red-500/10 border border-red-500/20 rounded-full text-red-400 text-xs">
                            <AlertCircle size={12} />
                            <span>Backend Disconnected</span>
                        </div>
                    </div>
                )}
                <div ref={chatEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-5 bg-[#0d0d10] border-t border-white/5">
                <div className="relative group">
                    <textarea
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' && !e.shiftKey) {
                                e.preventDefault();
                                handleSend();
                            }
                        }}
                        placeholder={apiStatus === 'online' ? "Analyze function behavior..." : "Waiting for connection..."}
                        disabled={apiStatus !== 'online'}
                        className="w-full bg-zinc-900/50 border border-white/10 rounded-xl px-4 py-3 pr-12 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all resize-none h-24 disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                    <button
                        onClick={handleSend}
                        disabled={!input.trim() || apiStatus !== 'online'}
                        className="absolute bottom-3 right-3 p-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:hover:bg-indigo-600 text-white rounded-lg transition-all shadow-lg shadow-indigo-900/20 hover:scale-105 active:scale-95"
                    >
                        <Send size={16} />
                    </button>
                </div>
                <div className="mt-3 flex items-center justify-between px-1">
                    <div className="flex items-center gap-1.5">
                        <div className={`w-1.5 h-1.5 rounded-full ${apiStatus === 'online' ? 'bg-emerald-500' : 'bg-zinc-700'}`} />
                        <span className="text-[10px] text-zinc-500 font-mono tracking-tighter uppercase">RRF Engine</span>
                    </div>
                    <span className="text-[10px] text-zinc-600 font-mono tracking-tighter uppercase opacity-50">v0.1.0</span>
                </div>
            </div>
        </div>
    );
}
