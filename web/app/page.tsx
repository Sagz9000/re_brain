'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Terminal, Shield, Cpu, BookOpen, Layers } from 'lucide-react';

export default function Home() {
  const [messages, setMessages] = useState([
    { role: 'system', content: 'reAIghidra systems active. Knowledge Streams connected: API, Patterns, Malware, Experts.' }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsTyping(true);

    try {
      const response = await fetch('http://localhost:8000/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: input }),
      });
      const data = await response.json();

      setMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (error) {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Connection to re-api failed. Make sure the container is running.' }]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0c] text-slate-100 font-sans selection:bg-purple-500/30">
      {/* Header */}
      <header className="h-14 border-b border-white/5 bg-black/40 backdrop-blur-md flex items-center justify-between px-6 z-10">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-purple-500/20">
            <Cpu size={18} className="text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            reAIghidra <span className="text-xs font-mono text-purple-400 opacity-60 ml-2">v0.1.0-alpha</span>
          </h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-green-500/10 border border-green-500/20 rounded-full">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-[10px] font-medium text-green-400 uppercase tracking-wider">Kernels Online</span>
          </div>
          <button className="text-slate-400 hover:text-white transition-colors">
            <Shield size={20} />
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Ghidra Panel */}
        <div className="flex-1 border-r border-white/5 relative group">
          <div className="absolute top-4 left-4 z-20 flex gap-2">
            <div className="px-3 py-1.5 bg-black/60 backdrop-blur-md border border-white/10 rounded-md flex items-center gap-2 text-xs font-medium">
              <Terminal size={14} className="text-purple-400" />
              <span>Ghidra Environment</span>
            </div>
          </div>
          <iframe
            src="http://localhost:6080/vnc.html?autoconnect=true&resize=scale"
            className="w-full h-full border-none opacity-90 hover:opacity-100 transition-opacity"
            title="Ghidra Workspace"
          />
          {/* Overlay info if VNC fails */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
            <div className="bg-black/80 px-4 py-2 rounded-lg border border-white/5 text-xs text-slate-500 italic">
              Interactive VNC via noVNC (Port 6080)
            </div>
          </div>
        </div>

        {/* Right: AI Intelligence Panel */}
        <div className="w-[480px] flex flex-col bg-[#0d0d0f]">
          <div className="p-4 border-b border-white/5 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-widest">
              <Layers size={16} className="text-purple-500" />
              Intelligence
            </div>
            <div className="flex gap-1">
              <div className="p-1 hover:bg-white/5 rounded cursor-help" title="API Reference Active">
                <BookOpen size={14} className="text-blue-400" />
              </div>
              <div className="p-1 hover:bg-white/5 rounded cursor-help" title="Malware Tactics Active">
                <Shield size={14} className="text-red-400" />
              </div>
            </div>
          </div>

          {/* Chat Feed */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-white/5">
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] px-4 py-2.5 rounded-2xl text-sm ${m.role === 'user'
                    ? 'bg-purple-600 text-white rounded-tr-none'
                    : m.role === 'system'
                      ? 'bg-slate-800/30 border border-white/5 text-slate-400 italic font-mono text-xs'
                      : 'bg-white/5 border border-white/10 text-slate-200 rounded-tl-none'
                  }`}>
                  {m.content}
                </div>
              </div>
            ))}
            {isTyping && (
              <div className="flex justify-start">
                <div className="bg-white/5 border border-white/10 px-4 py-2 rounded-2xl rounded-tl-none flex gap-1">
                  <div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" />
                  <div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce [animation-delay:0.2s]" />
                  <div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce [animation-delay:0.4s]" />
                </div>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Input Area */}
          <div className="p-4 bg-black/20 border-t border-white/5">
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
                placeholder="Analyze behavior or ask about patterns..."
                className="w-full bg-[#151518] border border-white/10 rounded-xl px-4 py-3 pr-12 text-sm focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/20 transition-all resize-none h-20"
              />
              <button
                onClick={handleSend}
                disabled={!input.trim()}
                className="absolute bottom-3 right-3 p-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:hover:bg-purple-600 text-white rounded-lg transition-all shadow-lg shadow-purple-900/20"
              >
                <Send size={18} />
              </button>
            </div>
            <div className="mt-2 flex items-center justify-between px-1">
              <span className="text-[10px] text-slate-600 font-mono tracking-tighter uppercase">RRF Engine: Active</span>
              <span className="text-[10px] text-slate-600 font-mono tracking-tighter uppercase">Model: Qwen3:8B</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
