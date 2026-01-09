'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, AlertCircle } from 'lucide-react';

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
        { role: 'assistant', content: "Hello! I'm re-Brain. Upload a binary or ask me about the analysis." }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const API_URL = 'http://localhost:8005';

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
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
        <div className="flex-1 max-w-[500px] flex flex-col bg-[#09090b] border-l border-white/5 shadow-2xl z-20">
            {/* Minimal Header */}
            <div className="h-14 border-b border-white/5 flex items-center justify-between px-6 bg-[#09090b]/95 backdrop-blur shrink-0">
                <span className="text-sm font-semibold text-zinc-300">AI Analyst</span>
                <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${apiStatus === 'online' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-red-500'}`} />
                    <span className="text-[10px] text-zinc-500 uppercase tracking-widest">{apiStatus}</span>
                </div>
            </div>

            {/* Messages Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-zinc-800 scrollbar-track-transparent">
                {messages.map((m, i) => (
                    <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        {m.role === 'assistant' && (
                            <div className="w-8 h-8 rounded-full bg-indigo-500/10 flex items-center justify-center mr-2 mt-1 shrink-0">
                                <Sparkles size={14} className="text-indigo-400" />
                            </div>
                        )}
                        <div className={`
                            max-w-[80%] px-4 py-3 text-sm leading-relaxed shadow-md break-words
                            ${m.role === 'user'
                                ? 'bg-indigo-600 text-white rounded-2xl rounded-tr-sm'
                                : 'bg-zinc-800/70 text-zinc-200 border border-white/5 rounded-2xl rounded-tl-sm'
                            }
                        `}>
                            {m.content}
                        </div>
                    </div>
                ))}

                {isTyping && (
                    <div className="flex justify-start">
                        <div className="w-8 h-8 rounded-full bg-indigo-500/10 flex items-center justify-center mr-2 mt-1 shrink-0">
                            <Sparkles size={14} className="text-indigo-400" />
                        </div>
                        <div className="bg-zinc-800/70 border border-white/5 px-4 py-3 rounded-2xl rounded-tl-sm flex gap-1.5 items-center">
                            <div className="w-1.5 h-1.5 bg-zinc-400 rounded-full animate-bounce" />
                            <div className="w-1.5 h-1.5 bg-zinc-400 rounded-full animate-bounce [animation-delay:0.2s]" />
                            <div className="w-1.5 h-1.5 bg-zinc-400 rounded-full animate-bounce [animation-delay:0.4s]" />
                        </div>
                    </div>
                )}

                {apiStatus === 'offline' && (
                    <div className="flex justify-center py-2">
                        <div className="flex items-center gap-2 px-3 py-1 bg-red-500/10 border border-red-500/20 rounded-full text-red-400 text-xs">
                            <AlertCircle size={12} />
                            <span>Backend Disconnected</span>
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-4 bg-[#09090b] border-t border-white/5 shrink-0">
                <div className="relative flex items-end gap-2 bg-zinc-900/60 border border-white/10 rounded-xl p-2 focus-within:border-indigo-500/50 focus-within:ring-1 focus-within:ring-indigo-500/20 transition-all">
                    <textarea
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' && !e.shiftKey) {
                                e.preventDefault();
                                handleSend();
                            }
                        }}
                        placeholder="Ask about the analysis..."
                        disabled={apiStatus !== 'online'}
                        className="flex-1 bg-transparent border-none text-sm text-zinc-200 placeholder:text-zinc-600 focus:ring-0 resize-none max-h-32 min-h-[44px] py-3 px-2 disabled:opacity-50"
                        rows={1}
                        style={{ height: 'auto', minHeight: '44px' }}
                    />
                    <button
                        onClick={handleSend}
                        disabled={!input.trim() || apiStatus !== 'online'}
                        className="p-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:hover:bg-indigo-600 text-white rounded-lg transition-all shadow-lg hover:scale-105 active:scale-95 mb-0.5"
                    >
                        <Send size={16} />
                    </button>
                </div>
                <div className="mt-2 text-center text-[10px] text-zinc-600 font-mono">
                    re-Brain AI v1.0 • Connected to Ghidra
                </div>
            </div>
        </div>
    );
}
