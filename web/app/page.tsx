'use client';

import { useState, useEffect } from 'react';
import WindowFrame from './components/WindowFrame';
import ProjectExplorer from './components/ProjectExplorer';
import DockedChat from './components/DockedChat';
import HexViewer from './components/HexViewer';
import FunctionTable from './components/FunctionTable';
import CodeViewer from './components/CodeViewer';
import StringsViewer from './components/StringsViewer';
import FileUpload from './components/FileUpload';
import ActivityLog from './components/ActivityLog';
import {
  Code, Sparkles, Terminal, Files, Search, Settings, Box,
  FolderTree, GitGraph, ListTree, LayoutDashboard, Binary, FileCode, Type, Upload, X
} from 'lucide-react';
import ProgramTree from './components/ProgramTree';
import FunctionGraph from './components/FunctionGraph';

interface WindowState {
  id: string;
  title: string;
  type: 'project' | 'chat' | 'hex' | 'functions' | 'decompile' | 'strings' | 'dashboard' | 'output' | 'tree' | 'graph';
  isOpen: boolean;
  zIndex: number;
  initialPos: { x: number, y: number };
  initialSize: { w: number, h: number };
  icon: any;
}

export default function Home() {
  const [apiStatus, setApiStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [files, setFiles] = useState<string[]>([]);
  const [activeFile, setActiveFile] = useState<string | null>(null);
  const [selectedFunction, setSelectedFunction] = useState<{ name: string, address: string } | null>(null);
  const [showUpload, setShowUpload] = useState(false);

  // Window Z-Index Tracker
  const [topZ, setTopZ] = useState(10);

  // Initial Window States
  const [windows, setWindows] = useState<WindowState[]>([
    { id: 'project', title: 'File Explorer', type: 'project', isOpen: true, zIndex: 1, initialPos: { x: 80, y: 20 }, initialSize: { w: 260, h: 500 }, icon: Files },
    { id: 'dashboard', title: 'System Overview', type: 'dashboard', isOpen: true, zIndex: 0, initialPos: { x: 360, y: 20 }, initialSize: { w: 800, h: 500 }, icon: LayoutDashboard },
    { id: 'chat', title: 're-Brain-AI', type: 'chat', isOpen: true, zIndex: 5, initialPos: { x: 1180, y: 20 }, initialSize: { w: 320, h: 800 }, icon: Sparkles },
    { id: 'output', title: 'Activity Output', type: 'output', isOpen: true, zIndex: 2, initialPos: { x: 360, y: 540 }, initialSize: { w: 800, h: 280 }, icon: Terminal },
    { id: 'hex', title: 'Hex Data', type: 'hex', isOpen: false, zIndex: 3, initialPos: { x: 400, y: 100 }, initialSize: { w: 700, h: 450 }, icon: Binary },
    { id: 'functions', title: 'Symbol Tree', type: 'functions', isOpen: false, zIndex: 3, initialPos: { x: 450, y: 150 }, initialSize: { w: 600, h: 400 }, icon: FileCode },
    { id: 'strings', title: 'Strings', type: 'strings', isOpen: false, zIndex: 3, initialPos: { x: 500, y: 200 }, initialSize: { w: 500, h: 400 }, icon: Type },
    { id: 'decompile', title: 'Decompilation', type: 'decompile', isOpen: false, zIndex: 4, initialPos: { x: 550, y: 250 }, initialSize: { w: 800, h: 600 }, icon: Code },
  ]);

  useEffect(() => {
    fetchFiles();
    const interval = setInterval(fetchFiles, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchFiles = async () => {
    try {
      const res = await fetch('http://localhost:8005/binaries');
      const data = await res.json();
      if (Array.isArray(data)) setFiles(data);
    } catch (e) { console.error(e) }
  };

  const toggleWindow = (id: string, forceOpen = false) => {
    setWindows((prev: WindowState[]) => {
      const next = prev.map(w => {
        if (w.id === id) {
          const nextOpen = forceOpen || !w.isOpen;
          return { ...w, isOpen: nextOpen, zIndex: nextOpen ? topZ + 1 : w.zIndex };
        }
        return w;
      });
      return next;
    });
    setTopZ((prev: number) => prev + 1);
  };

  const focusWindow = (id: string) => {
    setWindows((prev: WindowState[]) => prev.map(w => {
      if (w.id === id) return { ...w, zIndex: topZ + 1 };
      return w;
    }));
    setTopZ((prev: number) => prev + 1);
  };

  const closeWindow = (id: string) => {
    setWindows((prev: WindowState[]) => prev.map(w => w.id === id ? { ...w, isOpen: false } : w));
  };

  const onSelectFunction = (func: { name: string, address: string }) => {
    setSelectedFunction(func);
    toggleWindow('decompile', true);
  };

  const handleUiCommand = (cmd: any) => {
    if (!cmd || !cmd.action) return;
    if (cmd.action === 'SWITCH_TAB') {
      const typeMap: Record<string, string> = {
        'hex': 'hex',
        'functions': 'functions',
        'strings': 'strings',
        'dashboard': 'dashboard'
      };
      const winId = typeMap[cmd.tab] || cmd.tab;

      if (cmd.file) setActiveFile(cmd.file);
      if (cmd.function && cmd.address) {
        setSelectedFunction({ name: cmd.function, address: cmd.address });
        toggleWindow('decompile', true);
      } else if (winId) {
        toggleWindow(winId, true);
      }
    }
  };

  const handleDeleteFile = async (name: string) => {
    try {
      await fetch(`http://localhost:8005/binary/${name}`, { method: 'DELETE' });
      if (activeFile === name) {
        setActiveFile(null);
        setSelectedFunction(null);
      }
      fetchFiles();
    } catch (e) { console.error(e) }
  };

  return (
    <div className="flex h-screen bg-[#020203] text-zinc-100 font-sans overflow-hidden relative">
      <div className="absolute inset-0 z-0 bg-grid-white/[0.02] bg-[size:40px_40px] pointer-events-none" />
      <div className="absolute inset-0 z-0 bg-gradient-to-tr from-indigo-500/5 via-transparent to-transparent pointer-events-none" />

      <div className="w-16 bg-[#09090b]/80 backdrop-blur-md border-r border-white/5 flex flex-col items-center py-4 gap-4 z-50">
        <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center mb-4 shadow-lg shadow-indigo-500/20">
          <Box className="text-white" size={20} />
        </div>

        {windows.map((w: WindowState) => (
          <button
            key={w.id}
            onClick={() => toggleWindow(w.id)}
            className={`w-10 h-10 rounded-lg flex items-center justify-center transition-all duration-200 group relative ${w.isOpen ? 'bg-white/10 text-indigo-400' : 'text-zinc-500 hover:bg-white/5 hover:text-zinc-300'}`}
          >
            <w.icon size={20} />
            {w.isOpen && <div className="absolute left-0 w-1 h-4 bg-indigo-500 rounded-r-full" />}
            <div className="absolute left-full ml-3 px-2 py-1 bg-zinc-800 text-white text-[10px] rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50">
              {w.title}
            </div>
          </button>
        ))}

        <div className="mt-auto flex flex-col gap-4">
          <button onClick={() => setShowUpload(true)} className="w-10 h-10 text-zinc-500 hover:text-indigo-400 flex items-center justify-center"><Upload size={20} /></button>
          <button className="w-10 h-10 text-zinc-500 hover:text-zinc-300 flex items-center justify-center"><Settings size={20} /></button>
        </div>
      </div>

      <main className="flex-1 relative overflow-hidden z-10">
        {windows.map((win: WindowState) => win.isOpen && (
          <WindowFrame
            key={win.id}
            id={win.id}
            title={win.title}
            icon={<win.icon size={14} />}
            initialPos={win.initialPos}
            initialSize={win.initialSize}
            zIndex={win.zIndex}
            onClose={() => closeWindow(win.id)}
            onFocus={() => focusWindow(win.id)}
          >
            {win.type === 'project' && (
              <ProjectExplorer
                files={files} activeFile={activeFile}
                setActiveFile={(f) => { setActiveFile(f); setSelectedFunction(null); }}
                onUploadClick={() => setShowUpload(true)}
                onDeleteFile={handleDeleteFile}
              />
            )}
            {win.type === 'tree' && <ProgramTree file={activeFile} />}
            {win.type === 'graph' && <FunctionGraph />}
            {win.type === 'dashboard' && (
              <div className="flex-1 p-6 overflow-auto">
                <h2 className="text-xl font-bold mb-6 flex items-center gap-2">
                  <LayoutDashboard size={20} className="text-indigo-400" />
                  Project Dashboard
                </h2>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-white/5 p-4 rounded-lg border border-white/5">
                    <span className="text-[10px] text-zinc-500 uppercase">Binaries</span>
                    <p className="text-2xl font-mono">{files.length}</p>
                  </div>
                  <div className="bg-white/5 p-4 rounded-lg border border-white/5">
                    <span className="text-[10px] text-zinc-500 uppercase">Status</span>
                    <p className="text-sm font-bold text-emerald-400">{apiStatus}</p>
                  </div>
                </div>
                <div className="mt-8">
                  <h3 className="text-xs font-bold text-zinc-400 mb-4 uppercase tracking-widest">Recent Activity</h3>
                  <ActivityLog />
                </div>
              </div>
            )}
            {win.type === 'chat' && (
              <DockedChat
                apiStatus={apiStatus}
                onApiStatusChange={setApiStatus}
                onCommand={handleUiCommand}
              />
            )}
            {win.type === 'output' && <ActivityLog />}
            {win.type === 'hex' && activeFile && <HexViewer file={activeFile} />}
            {win.type === 'hex' && !activeFile && <NoFileSelected />}
            {win.type === 'functions' && activeFile && <FunctionTable file={activeFile} onSelectFunction={onSelectFunction} />}
            {win.type === 'functions' && !activeFile && <NoFileSelected />}
            {win.type === 'strings' && activeFile && <StringsViewer file={activeFile} />}
            {win.type === 'strings' && !activeFile && <NoFileSelected />}
            {win.type === 'decompile' && activeFile && selectedFunction && (
              <CodeViewer file={activeFile} address={selectedFunction.address} functionName={selectedFunction.name} />
            )}
            {win.type === 'decompile' && (!activeFile || !selectedFunction) && <NoFunctionSelected />}
          </WindowFrame>
        ))}
      </main>

      {showUpload && (
        <div className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-md flex items-center justify-center p-4">
          <div className="relative w-full max-w-md bg-[#09090b] border border-white/10 rounded-xl p-6 shadow-2xl overflow-hidden">
            <div className="absolute inset-x-0 top-0 h-1 bg-indigo-500" />
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-sm font-bold text-zinc-200 uppercase tracking-widest">Import Content</h3>
              <button onClick={() => setShowUpload(false)} className="text-zinc-500 hover:text-white"><X size={16} /></button>
            </div>
            <FileUpload onUploadComplete={() => { setShowUpload(false); fetchFiles(); }} />
          </div>
        </div>
      )}
    </div>
  );
}

function NoFileSelected() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 bg-[#0c0c0e]/30 backdrop-blur-sm p-12 text-center">
      <Files size={40} className="mb-4 opacity-20" />
      <p className="italic text-sm">Select a binary from the File Explorer to analyze its contents</p>
      <div className="mt-4 w-12 h-0.5 bg-indigo-500/20 rounded-full" />
    </div>
  )
}

function NoFunctionSelected() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 bg-[#0c0c0e]/30 backdrop-blur-sm p-12 text-center">
      <Code size={40} className="mb-4 opacity-20" />
      <p className="italic text-sm">Select a function from the Symbol Tree to generate decompiled C code</p>
      <div className="mt-4 w-12 h-0.5 bg-indigo-500/20 rounded-full" />
    </div>
  )
}
