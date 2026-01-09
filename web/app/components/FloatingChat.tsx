'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, AlertCircle, MessageSquare, X, Minimize2, Maximize2 } from 'lucide-react';

interface FloatingChatProps {
    apiStatus: 'online' | 'offline' | 'checking';
    onApiStatusChange: (status: 'online' | 'offline' | 'checking') => void;
}

interface Message {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export default function FloatingChat({ apiStatus, onApiStatusChange }: FloatingChatProps) {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState<Message[]>([
        { role: 'assistant', content: "I'm ready to analyze. Ask me about functions, strings, or vulnerability patterns." }
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
    }, [messages, isTyping, isOpen]);

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

    if (!isOpen) {
        return (
            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-6 right-6 w-14 h-14 bg-indigo-600 hover:bg-indigo-500 rounded-full shadow-2xl flex items-center justify-center transition-all hover:scale-110 z-50 group"
            >
                <div className="absolute -top-1 -right-1 w-4 h-4 bg-emerald-500 rounded-full border-2 border-[#09090b]" />
                <MessageSquare className="text-white" />
            </button>
        );
    }

    return (
        <div className="fixed bottom-6 right-6 w-[400px] h-[600px] bg-[#09090b] border border-white/10 rounded-2xl shadow-2xl flex flex-col z-50 overflow-hidden animate-in slide-in-from-bottom-10 fade-in duration-200">
            {/* Header */}
            <div className="h-12 border-b border-white/5 flex items-center justify-between px-4 bg-zinc-900/50 backdrop-blur">
                <div className="flex items-center gap-2">
                    <Sparkles size={14} className="text-indigo-400" />
                    <span className="text-sm font-semibold text-zinc-200">AI Analyst</span>
                    <div className={`w-1.5 h-1.5 rounded-full ${apiStatus === 'online' ? 'bg-emerald-500' : 'bg-red-500'} ml-2`} />
                </div>
                <button onClick={() => setIsOpen(false)} className="p-1 hover:bg-white/10 rounded-md transition-colors text-zinc-400">
                    <X size={16} />
                </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-zinc-800">
                {messages.map((m, i) => (
                    <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div className={`
                            max-w-[85%] px-3 py-2 text-sm leading-relaxed shadow-sm break-words
                            ${m.role === 'user'
                                ? 'bg-indigo-600 text-white rounded-2xl rounded-tr-sm'
                                : 'bg-zinc-800 text-zinc-200 rounded-2xl rounded-tl-sm border border-white/5'
                            }
                        `}>
                            {m.content}
                        </div>
                    </div>
                ))}
                {isTyping && (
                    <div className="flex justify-start">
                        <div className="bg-zinc-800 border border-white/5 px-3 py-2 rounded-2xl rounded-tl-sm flex gap-1 items-center">
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
                <div className="flex gap-2">
                    <input
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                        placeholder="Ask generic questions..."
                        className="flex-1 bg-zinc-800 border-none rounded-lg px-3 py-2 text-sm text-zinc-200 focus:ring-1 focus:ring-indigo-500"
                    />
                    <button onClick={handleSend} className="p-2 bg-indigo-600 rounded-lg text-white hover:bg-indigo-500">
                        <Send size={16} />
                    </button>
                </div>
            </div>
        </div>
    );
}
