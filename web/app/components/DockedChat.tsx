'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, MessageSquare, Trash2, Crosshair, Code, Copy, Check, Play } from 'lucide-react';
import { API_URL } from '../utils';

// ... (keep interfaces)

const ThoughtBlock = ({ thought }: { thought: string }) => {
    const [isExpanded, setIsExpanded] = useState(false);

    if (!thought.trim()) return null;

    return (
        <div className="mb-3 border-l-2 border-indigo-500/30 pl-3 py-1 bg-white/5 rounded-r-lg group transition-all">
            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="flex items-center gap-2 text-[10px] uppercase tracking-widest text-indigo-400 font-bold hover:text-indigo-300 transition-colors"
            >
                <div className={`w-1.5 h-1.5 rounded-full bg-indigo-500 ${isExpanded ? 'animate-pulse' : 'opacity-50'}`} />
                {isExpanded ? 'Hide Reasoning' : 'Show Reasoning'}
            </button>
            {isExpanded && (
                <div className="text-xs text-zinc-500 mt-2 italic leading-relaxed animate-in fade-in slide-in-from-top-1 duration-200">
                    {thought}
                </div>
            )}
        </div>
    );
};

const CodeBlock = ({ code, language }: { code: string, language: string }) => {
    const [output, setOutput] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [isRunning, setIsRunning] = useState(false);
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        await navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleRun = async () => {
        setIsRunning(true);
        setOutput(null);
        setError(null);
        try {
            const res = await fetch(`${API_URL}/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            });
            const data = await res.json();
            if (data.error) {
                setError(data.error);
            }
            if (data.output) {
                setOutput(data.output);
            }
            if (!data.error && !data.output) {
                setOutput("(No output)");
            }
        } catch (e: any) {
            setError(e.message || "Failed to run code");
        } finally {
            setIsRunning(false);
        }
    };

    const isPython = language.toLowerCase() === 'python' || language.toLowerCase() === 'py';

    return (
        <div className="my-2 rounded overflow-hidden border border-white/10 bg-[#1e1e20]">
            {/* Header */}
            <div className="flex items-center justify-between px-3 py-1.5 bg-[#27272a] border-b border-white/5">
                <span className="text-xs text-zinc-400 font-mono lowercase">{language || 'text'}</span>
                <div className="flex items-center gap-2">
                    {isPython && (
                        <button
                            onClick={handleRun}
                            disabled={isRunning}
                            className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/30 transition-colors disabled:opacity-50"
                        >
                            <Play size={10} className={isRunning ? "animate-spin" : ""} />
                            {isRunning ? 'Running...' : 'Run'}
                        </button>
                    )}
                    <button
                        onClick={handleCopy}
                        className="text-zinc-500 hover:text-zinc-300 transition-colors"
                        title="Copy code"
                    >
                        {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    </button>
                </div>
            </div>

            {/* Code */}
            <div className="bg-black/50 p-3 overflow-x-auto">
                <pre className="text-xs font-mono text-zinc-300 pointer-events-auto select-text whitespace-pre-wrap break-all">
                    {code}
                </pre>
            </div>

            {/* Output Console */}
            {(output || error) && (
                <div className="border-t border-white/10 bg-black/80 p-2 font-mono text-[10px]">
                    <div className="text-zinc-500 mb-1 uppercase tracking-wider text-[9px]">Console Output</div>
                    <pre className={`whitespace-pre-wrap break-all ${error ? 'text-red-400' : 'text-zinc-300'}`}>
                        {error || output}
                    </pre>
                </div>
            )}
        </div>
    );
};

const FormattedMessage = ({ content, onLinkClick, onFunctionClick }: { content: string, onLinkClick?: (addr: string) => void, onFunctionClick?: (name: string, addr: string) => void }) => {
    // 1. Extract thinking process
    let thought = "";
    let cleanContent = content;
    const thinkMatch = content.match(/<think>([\s\S]*?)<\/think>/i);
    if (thinkMatch) {
        thought = thinkMatch[1].trim();
        cleanContent = content.replace(/<think>[\s\S]*?<\/think>/i, '').trim();
    }

    // 2. Split by code blocks
    const parts = cleanContent.split(/(```[\s\S]*?```)/g);

    const renderTextWithLinks = (text: string) => {
        // Process line for bold, addresses, and functions
        // Tries to catch [0x...], 0x..., [func:...], sub_XXXX, fun_XXXX, and **bold**
        const tokens = text.split(/(\[func:[^\]]+\])|(\[0x[a-fA-F0-9]+\])|(0x[a-fA-F0-9]{4,})|(\*\*.*?\*\*)|(sub_[a-fA-F0-9]+)|(fun_[a-fA-F0-9]+)/g).filter(Boolean);

        return tokens.map((token, k) => {
            if (token.startsWith('**') && token.endsWith('**')) {
                return <strong key={k} className="text-zinc-100 font-semibold">{token.slice(2, -2)}</strong>;
            }
            // Function link: [func:FunctionName@0x12345678]
            if (token.match(/^\[func:[^\]]+\]$/)) {
                const match = token.match(/\[func:\s*([^@]+?)\s*@\s*(0x[a-fA-F0-9]+)\s*\]/);
                if (match) {
                    const [, funcName, funcAddr] = match;
                    return (
                        <span
                            key={k}
                            onClick={() => onFunctionClick && onFunctionClick(funcName, funcAddr)}
                            className="mx-1 px-2 py-0.5 bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30 cursor-pointer hover:bg-emerald-500/40 hover:text-white transition-colors font-mono text-xs select-none inline-flex items-center gap-1"
                            title={`Open decompiler for ${funcName}`}
                        >
                            <Code size={10} />
                            {funcName}
                        </span>
                    );
                }
            }
            // Direct Function Name: sub_XXXX or fun_XXXX
            if (token.match(/^(sub|fun)_[a-fA-F0-9]+$/)) {
                // Infer address from name
                const parts = token.split('_');
                const addrStr = parts[1];
                // Check if valid hex
                if (/^[a-fA-F0-9]+$/.test(addrStr)) {
                    const addr = "0x" + addrStr;
                    return (
                        <span
                            key={k}
                            onClick={() => onFunctionClick && onFunctionClick(token, addr)}
                            className="mx-1 px-2 py-0.5 bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30 cursor-pointer hover:bg-emerald-500/40 hover:text-white transition-colors font-mono text-xs select-none inline-flex items-center gap-1"
                            title={`Open decompiler for ${token}`}
                        >
                            <Code size={10} />
                            {token}
                        </span>
                    );
                }
            }

            // Address link: [0x12345678] or 0x12345678
            if (token.match(/^\[?0x[a-fA-F0-9]{4,}\]?$/)) {
                const addr = token.replace(/[\[\]]/g, '');
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
            return <span key={k}>{token}</span>;
        });
    };

    return (
        <div className="text-sm space-y-3 relative">
            {thought && <ThoughtBlock thought={thought} />}
            {parts.map((part, i) => {
                if (part.startsWith('```')) {
                    const match = part.match(/```(\w*)\n?([\s\S]*?)```/);
                    const lang = match ? match[1] : '';
                    const code = match ? match[2] : part.replace(/```/g, '');
                    return <CodeBlock key={i} code={code.trim()} language={lang} />;
                }
                // Handle bold, lists, addresses, and functions
                return (
                    <div key={i} className="space-y-2">
                        {part.split('\n').map((line, j) => {
                            // Skip empty lines but preserve spacing
                            if (!line.trim()) return <div key={j} className="h-2" />;

                            // Headers
                            if (line.startsWith('### ')) return <h3 key={j} className="text-indigo-400 font-bold mt-3 mb-1 text-base">{renderTextWithLinks(line.replace('### ', ''))}</h3>;
                            if (line.startsWith('## ')) return <h2 key={j} className="text-indigo-300 font-bold mt-4 mb-2 text-lg border-b border-indigo-500/30 pb-1">{renderTextWithLinks(line.replace('## ', ''))}</h2>;

                            return (
                                <div key={j} className={line.startsWith('- ') ? "ml-6 flex gap-2 my-1.5" : "my-1.5 leading-relaxed"}>
                                    {line.startsWith('- ') && <span className="text-zinc-500 mt-0.5">•</span>}
                                    <span className="flex-1">
                                        {renderTextWithLinks(line.startsWith('- ') ? line.replace('- ', '') : line)}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                );
            })}
            <div className="flex justify-end mt-2 pt-2 border-t border-white/5 items-center gap-2">
                <CopyButton content={cleanContent} />
            </div>
        </div>
    );
};

const CopyButton = ({ content }: { content: string }) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        await navigator.clipboard.writeText(content);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <button
            onClick={handleCopy}
            className="p-1.5 bg-black/40 hover:bg-black/60 text-zinc-400 hover:text-white rounded backdrop-blur-sm transition-all"
            title="Copy raw markdown"
        >
            {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
        </button>
    );
};

export default function DockedChat({
    apiStatus,
    onApiStatusChange,
    onCommand,
    currentFile,
    currentFunction,
    currentAddress
}: DockedChatProps) {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);


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

    const handleFunctionClick = (name: string, addr: string) => {
        if (onCommand) {
            onCommand({
                action: 'SWITCH_TAB',
                tab: 'decompile',
                file: currentFile,
                function: name,
                address: addr
            });
        }
    };

    const handleSend = async () => {
        if (!input.trim()) return;
        const userMessage = { role: 'user', content: input } as Message;
        const newHistory = [...messages, userMessage];
        setMessages(newHistory);
        setInput('');
        setIsTyping(true);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 90000); // 90s timeout

        try {
            const response = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: controller.signal,
                body: JSON.stringify({
                    query: input,
                    history: newHistory,
                    current_file: currentFile,
                    current_function: currentFunction,
                    current_address: currentAddress
                }),
            });
            clearTimeout(timeoutId);
            if (!response.ok) throw new Error(response.statusText);
            const data = await response.json();
            let fullText = data.response || data.error || "No response from AI.";
            let textToDisplay = fullText;

            // UI Command Logic - Extract ANY JSON with "action" and execute it
            try {
                // Find all JSON blocks (anything between braces)
                const jsonMatches = fullText.match(/\{[\s\S]*?\}/g);
                if (jsonMatches) {
                    for (const matchStr of jsonMatches) {
                        try {
                            const cmd = JSON.parse(matchStr);
                            if (cmd.action || (Array.isArray(cmd) && cmd[0]?.action)) {
                                // Strip this JSON and any surrounding code block text from display
                                // Look for the code block that might contain this
                                const pattern = new RegExp("```json[\\s\\S]*?" + matchStr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + "[\\s\\S]*?```", "g");
                                textToDisplay = textToDisplay.replace(pattern, '').trim();

                                // Also strip naked command labels
                                const labels = [/UI_COMMAND:/gi, /COMMAND_BLOCK:/gi, /COMMANDS:/gi, /Action Required:/gi];
                                labels.forEach(l => { textToDisplay = textToDisplay.replace(l, '').trim(); });

                                // Execute
                                if (Array.isArray(cmd)) {
                                    cmd.forEach(c => onCommand && onCommand(c));
                                } else if (onCommand) {
                                    onCommand(cmd);
                                }
                            }
                        } catch (e) { /* Not a valid command JSON, ignore */ }
                    }
                }
            } catch (e) {
                console.error("Failed to parse commands from response", e);
            }

            setMessages(prev => [...prev, { role: 'assistant', content: textToDisplay }]);
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
                            {m.role === 'user' ? m.content : <FormattedMessage content={m.content} onLinkClick={handleLinkClick} onFunctionClick={handleFunctionClick} />}
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
