'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, MessageSquare } from 'lucide-react';

interface DockedChatProps {
    apiStatus: 'online' | 'offline' | 'checking';
    onApiStatusChange: (status: 'online' | 'offline' | 'checking') => void;
}

interface Message {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export default function DockedChat({ apiStatus, onApiStatusChange }: DockedChatProps) {
    const [messages, setMessages] = useState<Message[]>([
        { role: 'assistant', content: "I'm your analyis copilot. I have context on the open file." }
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
                if (res.ok) onApiStatusChange('online');
                else onApiStatusChange('offline');
            } catch (e) {
                onApiStatusChange('offline');
            }
        };
        checkHealth();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

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
        <div className="flex flex-col h-full bg-[#09090b] border-l border-white/5 w-80 shrink-0">
            {/* Header */}
            <div className="h-10 border-b border-white/5 flex items-center justify-between px-4 bg-zinc-900/50">
                <div className="flex items-center gap-2">
                    <Sparkles size={14} className="text-indigo-400" />
                    <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider">AI Copilot</span>
                </div>
                <div className={`w-1.5 h-1.5 rounded-full ${apiStatus === 'online' ? 'bg-emerald-500' : 'bg-red-500'}`} title={apiStatus} />
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-zinc-800">
                {messages.map((m, i) => (
                    <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div className={`
                            max-w-[90%] px-3 py-2 text-sm leading-relaxed shadow-sm break-words
                            ${m.role === 'user'
                                ? 'bg-indigo-600/20 text-indigo-100 rounded-lg border border-indigo-500/30'
                                : 'bg-zinc-800/50 text-zinc-300 rounded-lg border border-white/5'
                            }
                        `}>
                            {m.content}
                        </div>
                    </div>
                ))}
                {isTyping && (
                    <div className="flex justify-start">
                        <div className="bg-zinc-800/50 border border-white/5 px-3 py-2 rounded-lg flex gap-1 items-center">
                            <div className="w-1 h-1 bg-zinc-400 rounded-full animate-bounce" />
                            <div className="w-1 h-1 bg-zinc-400 rounded-full animate-bounce [animation-delay:0.2s]" />
                            <div className="w-1 h-1 bg-zinc-400 rounded-full animate-bounce [animation-delay:0.4s]" />
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-3 bg-zinc-900/50 border-t border-white/5">
                <div className="relative">
                    <input
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                        placeholder="Ask Copilot..."
                        className="w-full bg-zinc-800 border-none rounded-lg pl-3 pr-10 py-2.5 text-sm text-zinc-200 focus:ring-1 focus:ring-indigo-500"
                    />
                    <button
                        onClick={handleSend}
                        className="absolute right-2 top-2 p-0.5 text-zinc-400 hover:text-indigo-400 transition-colors"
                    >
                        <Send size={16} />
                    </button>
                </div>
            </div>
        </div>
    );
}
