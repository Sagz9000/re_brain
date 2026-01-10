'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, MessageSquare, Trash2 } from 'lucide-react';

interface DockedChatProps {
    apiStatus: 'online' | 'offline' | 'checking';
    onApiStatusChange: (status: 'online' | 'offline' | 'checking') => void;
    onCommand?: (cmd: any) => void;
}

interface Message {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export default function DockedChat({ apiStatus, onApiStatusChange, onCommand }: DockedChatProps) {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const API_URL = 'http://localhost:8005';

    // Load history
    useEffect(() => {
        const saved = localStorage.getItem('re_brain_chat_history');
        if (saved) {
            try {
                setMessages(JSON.parse(saved));
            } catch (e) {
                console.error("Failed to load chat history", e);
            }
        } else {
            setMessages([{ role: 'assistant', content: "I'm re-Brain-AI, your analysis copilot. I have context on the open file." }]);
        }
    }, []);

    // Save history
    useEffect(() => {
        if (messages.length > 0) {
            localStorage.setItem('re_brain_chat_history', JSON.stringify(messages));
        }
    }, [messages]);

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

    const handleClear = () => {
        const initialMsg: Message = { role: 'assistant', content: "Chat cleared. Ready for new analysis." };
        setMessages([initialMsg]);
        localStorage.setItem('re_brain_chat_history', JSON.stringify([initialMsg]));
    };

    const handleSend = async () => {
        if (!input.trim()) return;
        const userMessage = { role: 'user', content: input } as Message;
        const newHistory = [...messages, userMessage];
        setMessages(newHistory);
        setInput('');
        setIsTyping(true);

        try {
            const response = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: input,
                    history: newHistory
                }),
            });
            if (!response.ok) throw new Error(response.statusText);
            const data = await response.json();
            let text = data.response;

            // UI Command Logic - More robust parsing
            if (text.includes('UI_COMMAND:')) {
                const parts = text.split('UI_COMMAND:');
                text = parts[0].trim();
                const possibleJson = parts[1].trim();

                try {
                    // Try to find the first JSON object in the string
                    const jsonMatch = possibleJson.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        const cmd = JSON.parse(jsonMatch[0]);
                        if (onCommand) onCommand(cmd);
                    }
                } catch (e) {
                    console.error("Failed to parse UI command", e);
                }
            }

            setMessages(prev => [...prev, { role: 'assistant', content: text }]);
        } catch (error) {
            setMessages(prev => [...prev, { role: 'assistant', content: `Connection Failed: ${error}` }]);
            onApiStatusChange('offline');
        } finally {
            setIsTyping(false);
        }
    };

    return (
        <div className="flex flex-col h-full bg-[#09090b] flex-1">
            {/* Header with Clear Button */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 bg-[#121214]">
                <div className="flex items-center gap-2">
                    <Sparkles size={14} className="text-indigo-400" />
                    <span className="text-xs font-bold text-zinc-300">re-Brain-AI</span>
                </div>
                <button onClick={handleClear} className="text-zinc-500 hover:text-red-400 p-1 rounded hover:bg-white/5 transition-colors" title="Clear Chat">
                    <Trash2 size={14} />
                </button>
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
                        placeholder="Ask re-Brain-AI..."
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
