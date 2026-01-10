'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, MessageSquare, Trash2, Crosshair } from 'lucide-react';

interface DockedChatProps {
    apiStatus: 'online' | 'offline' | 'checking';
    onApiStatusChange: (status: 'online' | 'offline' | 'checking') => void;
    onCommand?: (cmd: any) => void;
}

interface Message {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

const FormattedMessage = ({ content, onLinkClick }: { content: string, onLinkClick?: (addr: string) => void }) => {
    // Basic markdown parser
    const parts = content.split(/(```[\s\S]*?```)/g);
    return (
        <div className="text-sm space-y-3">
            {parts.map((part, i) => {
                if (part.startsWith('```')) {
                    const code = part.replace(/```\w*\n?/, '').replace(/```$/, '');
                    return (
                        <pre key={i} className="bg-black/50 p-3 rounded text-xs overflow-x-auto font-mono text-zinc-300 pointer-events-auto select-text border border-zinc-700/50">
                            {code}
                        </pre>
                    );
                }
                // Handle bold, lists, and addresses
                return (
                    <div key={i} className="space-y-2">
                        {part.split('\n').map((line, j) => {
                            // Skip empty lines but preserve spacing
                            if (!line.trim()) return <div key={j} className="h-2" />;

                            // Headers
                            if (line.startsWith('### ')) return <h3 key={j} className="text-indigo-400 font-bold mt-3 mb-1 text-base">{line.replace('### ', '')}</h3>;
                            if (line.startsWith('## ')) return <h2 key={j} className="text-indigo-300 font-bold mt-4 mb-2 text-lg border-b border-indigo-500/30 pb-1">{line.replace('## ', '')}</h2>;

                            // Process line for bold and addresses
                            const tokens = line.split(/(\[0x[a-fA-F0-9]+\])|(\*\*.*?\*\*)/g).filter(Boolean);

                            return (
                                <div key={j} className={line.startsWith('- ') ? "ml-6 flex gap-2 my-1.5" : "my-1.5 leading-relaxed"}>
                                    {line.startsWith('- ') && <span className="text-zinc-500 mt-0.5">•</span>}
                                    <span className="flex-1">
                                        {tokens.map((token, k) => {
                                            if (token.startsWith('**') && token.endsWith('**')) {
                                                return <strong key={k} className="text-zinc-100 font-semibold">{token.slice(2, -2)}</strong>;
                                            }
                                            if (token.match(/^\[0x[a-fA-F0-9]+\]$/)) {
                                                const addr = token.slice(1, -1);
                                                return (
                                                    <span
                                                        key={k}
                                                        onClick={() => onLinkClick && onLinkClick(addr)}
                                                        className="mx-1 px-1.5 py-0.5 bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/30 cursor-pointer hover:bg-indigo-500/40 hover:text-white transition-colors font-mono text-xs select-none inline-flex items-center gap-1"
                                                        title={`Go to ${addr}`}
                                                    >
                                                        <Crosshair size={8} />
                                                        {addr}
                                                    </span>
                                                );
                                            }
                                            return <span key={k}>{line.startsWith('- ') ? token.replace('- ', '') : token}</span>
                                        })}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                );
            })}
        </div>
    );
};

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
    }, []);

    const handleClear = () => {
        const initialMsg: Message = { role: 'assistant', content: "Chat cleared. Ready for new analysis." };
        setMessages([initialMsg]);
        localStorage.setItem('re_brain_chat_history', JSON.stringify([initialMsg]));
    };

    const handleLinkClick = (addr: string) => {
        if (onCommand) {
            onCommand({ action: 'goto', target: addr });
        }
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
                            max-w-[90%] px-4 py-3 text-sm leading-relaxed shadow-sm break-words
                            ${m.role === 'user'
                                ? 'bg-indigo-600 text-white rounded-2xl rounded-tr-sm'
                                : 'bg-[#27272a] text-zinc-200 rounded-2xl rounded-tl-sm border border-white/5'}
                        `}>
                            {m.role === 'user' ? m.content : <FormattedMessage content={m.content} onLinkClick={handleLinkClick} />}
                        </div>
                    </div>
                ))}

                {isTyping && (
                    <div className="flex justify-start">
                        <div className="bg-[#27272a] px-4 py-2 rounded-2xl rounded-tl-sm border border-white/5 flex items-center gap-1">
                            <div className="w-1.5 h-1.5 bg-zinc-500 rounded-full animate-bounce [animation-delay:-0.3s]" />
                            <div className="w-1.5 h-1.5 bg-zinc-500 rounded-full animate-bounce [animation-delay:-0.15s]" />
                            <div className="w-1.5 h-1.5 bg-zinc-500 rounded-full animate-bounce" />
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-3 bg-[#121214] border-t border-white/5">
                <div className="relative flex items-center">
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                        placeholder="Ask about the binary..."
                        className="w-full bg-[#1e1e20] border border-white/10 rounded-full pl-4 pr-10 py-2.5 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 transition-all placeholder:text-zinc-600"
                    />
                    <button
                        onClick={handleSend}
                        disabled={!input.trim()}
                        className="absolute right-2 p-1.5 bg-indigo-600 text-white rounded-full hover:bg-indigo-500 disabled:opacity-50 disabled:hover:bg-indigo-600 transition-colors"
                    >
                        <Send size={14} />
                    </button>
                </div>
            </div>
        </div>
    );
}
