'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, Terminal, Shield, Cpu, BookOpen, Layers } from 'lucide-react';

export default function Home() {
  const [messages, setMessages] = useState([
    { role: 'system', content: 'reAIghidra systems active. Knowledge Streams connected: API, Patterns, Malware, Experts.' }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [apiStatus, setApiStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const chatEndRef = useRef<HTMLDivElement>(null);

  const API_URL = 'http://localhost:8005';

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Health Check
  useEffect(() => {
    const checkHealth = async () => {
      console.log('[UI] Checking API health at', `${API_URL}/health`);
      try {
        const res = await fetch(`${API_URL}/health`);
        if (res.ok) {
          console.log('[UI] API is ONLINE');
          setApiStatus('online');
        } else {
          console.warn('[UI] API returned non-OK status:', res.status);
          setApiStatus('offline');
        }
      } catch (e) {
        console.error('[UI] API Health Check Failed:', e);
        setApiStatus('offline');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000); // Poll every 30s
    return () => clearInterval(interval);
  }, []);

  const handleSend = async () => {
    if (!input.trim()) {
      console.log('[UI] Input empty, ignoring send.');
      return;
    }

    console.log('[UI] Sending message:', input);
    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsTyping(true);

    try {
      console.log('[UI] POSTing to', `${API_URL}/chat`);
      const response = await fetch(`${API_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: input }),
      });

      console.log('[UI] Response Status:', response.status);

      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }

      const data = await response.json();
      console.log('[UI] Received Data:', data);

      setMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (error) {
      console.error('[UI] Chat Request Failed:', error);
      setMessages(prev => [...prev, { role: 'assistant', content: `Connection Failed: ${error}` }]);
      setApiStatus('offline');
    } finally {
      setIsTyping(false);
    }
  };

  // Button Debug Handlers
  const handleFeatureClick = (feature: string) => {
    console.log(`[UI] Feature clicked: ${feature}`);
    alert(`Feature '${feature}' accessed. Check console for logs.`);
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
          <div className={`flex items-center gap-2 px-3 py-1 border rounded-full transition-colors ${apiStatus === 'online' ? 'bg-green-500/10 border-green-500/20 text-green-400' :
              apiStatus === 'offline' ? 'bg-red-500/10 border-red-500/20 text-red-400' :
                'bg-yellow-500/10 border-yellow-500/20 text-yellow-400'
            }`}>
            <div className={`w-2 h-2 rounded-full ${apiStatus === 'online' ? 'bg-green-500 animate-pulse' : apiStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-bounce'}`} />
            <span className="text-[10px] font-medium uppercase tracking-wider">
              {apiStatus === 'online' ? 'System Online' : apiStatus === 'offline' ? 'System Offline' : 'Checking...'}
            </span>
          </div>
          <button onClick={() => handleFeatureClick('Shield')} className="text-slate-400 hover:text-white transition-colors">
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
            <button
              onClick={() => {
                const frame = document.getElementById('ghidra-frame') as HTMLIFrameElement;
                if (frame) frame.src = frame.src; // Reload
                console.log('[UI] Reloading VNC frame');
              }}
              className="px-2 py-1.5 bg-black/60 hover:bg-white/10 backdrop-blur-md border border-white/10 rounded-md text-xs"
            >
              Reload VNC
            </button>
          </div>
          <iframe
            id="ghidra-frame"
            src="http://localhost:6080/vnc.html?autoconnect=true&resize=scale"
            className="w-full h-full border-none opacity-90 hover:opacity-100 transition-opacity"
            title="Ghidra Workspace"
            onError={() => console.error('[UI] Iframe load error')}
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
              <div onClick={() => handleFeatureClick('API Ref')} className="p-1 hover:bg-white/5 rounded cursor-pointer" title="API Reference Active">
                <BookOpen size={14} className="text-blue-400" />
              </div>
              <div onClick={() => handleFeatureClick('Tactics')} className="p-1 hover:bg-white/5 rounded cursor-pointer" title="Malware Tactics Active">
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
                placeholder={apiStatus === 'online' ? "Analyze behavior or ask about patterns..." : "Connecting to system..."}
                disabled={apiStatus !== 'online'}
                className="w-full bg-[#151518] border border-white/10 rounded-xl px-4 py-3 pr-12 text-sm focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/20 transition-all resize-none h-20 disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={handleSend}
                disabled={!input.trim() || apiStatus !== 'online'}
                className="absolute bottom-3 right-3 p-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:hover:bg-purple-600 text-white rounded-lg transition-all shadow-lg shadow-purple-900/20"
              >
                <Send size={18} />
              </button>
            </div>
            <div className="mt-2 flex items-center justify-between px-1">
              <span className="text-[10px] text-slate-600 font-mono tracking-tighter uppercase">{apiStatus === 'online' ? 'RRF Engine: Active' : 'RRF Engine: Offline'}</span>
              <span className="text-[10px] text-slate-600 font-mono tracking-tighter uppercase">Model: Qwen3:8B</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
