'use client';

import { useState, useEffect } from 'react';
import WindowFrame from './components/WindowFrame';
import ProjectExplorer from './components/ProjectExplorer';
import DockedChat from './components/DockedChat';
import HexViewer from './components/HexViewer';
import SymbolTree from './components/SymbolTree';
import CodeViewer from './components/CodeViewer';
import StringsViewer from './components/StringsViewer';
import FileUpload from './components/FileUpload';
import ActivityLog from './components/ActivityLog';
import ProgramTree from './components/ProgramTree';
import FunctionGraph from './components/FunctionGraph';
import DisassemblyView from './components/DisassemblyView';
import DataTypeManager from './components/DataTypeManager';
import CallTree from './components/CallTree';
import ScriptManager from './components/ScriptManager';
import BookmarkManager from './components/BookmarkManager';
import ProjectManager from './components/ProjectManager';

import {
  Code, Sparkles, Terminal, Files, Search, Settings, Box,
  FolderTree, GitGraph, ListTree, LayoutDashboard, Binary, FileCode, Type, Upload, X,
  AlignLeft, Database, GitCommit, Play, Bookmark
} from 'lucide-react';

interface WindowState {
  id: string;
  title: string;
  type: 'project' | 'chat' | 'hex' | 'symbol_tree' | 'decompile' | 'strings' | 'dashboard' | 'output' | 'tree' | 'graph' | 'listing' | 'datatypes' | 'call_tree' | 'scripts' | 'bookmarks' | 'projects';
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
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);
  const [showUpload, setShowUpload] = useState(false);

  // Window Z-Index Tracker
  const [topZ, setTopZ] = useState(10);

  // Initial Window States
  const [windows, setWindows] = useState<WindowState[]>([
    // Core Management
    { id: 'project', title: 'File Explorer', type: 'project', isOpen: true, zIndex: 1, initialPos: { x: 20, y: 20 }, initialSize: { w: 260, h: 600 }, icon: Files },
    { id: 'dashboard', title: 'System Overview', type: 'dashboard', isOpen: true, zIndex: 0, initialPos: { x: 300, y: 20 }, initialSize: { w: 800, h: 500 }, icon: LayoutDashboard },

    // Core Analysis
    { id: 'listing', title: 'Listing View', type: 'listing', isOpen: false, zIndex: 2, initialPos: { x: 300, y: 540 }, initialSize: { w: 800, h: 400 }, icon: AlignLeft },
    { id: 'symbol_tree', title: 'Symbol Tree', type: 'symbol_tree', isOpen: false, zIndex: 3, initialPos: { x: 1120, y: 20 }, initialSize: { w: 300, h: 400 }, icon: ListTree },
    { id: 'datatypes', title: 'Data Type Manager', type: 'datatypes', isOpen: false, zIndex: 3, initialPos: { x: 1120, y: 440 }, initialSize: { w: 300, h: 400 }, icon: Database },
    { id: 'tree', title: 'Program Tree', type: 'tree', isOpen: false, zIndex: 3, initialPos: { x: 300, y: 20 }, initialSize: { w: 300, h: 400 }, icon: FolderTree },

    // Views
    { id: 'decompile', title: 'Decompiler', type: 'decompile', isOpen: false, zIndex: 4, initialPos: { x: 620, y: 20 }, initialSize: { w: 500, h: 500 }, icon: Code },
    { id: 'graph', title: 'Function Graph', type: 'graph', isOpen: false, zIndex: 4, initialPos: { x: 400, y: 100 }, initialSize: { w: 600, h: 500 }, icon: GitGraph },
    { id: 'call_tree', title: 'Function Call Tree', type: 'call_tree', isOpen: false, zIndex: 4, initialPos: { x: 450, y: 150 }, initialSize: { w: 400, h: 500 }, icon: GitCommit },
    { id: 'hex', title: 'Bytes', type: 'hex', isOpen: false, zIndex: 3, initialPos: { x: 400, y: 400 }, initialSize: { w: 600, h: 300 }, icon: Binary },
    { id: 'strings', title: 'Defined Strings', type: 'strings', isOpen: false, zIndex: 3, initialPos: { x: 500, y: 200 }, initialSize: { w: 500, h: 400 }, icon: Type },

    // Tools
    { id: 'scripts', title: 'Script Manager', type: 'scripts', isOpen: false, zIndex: 5, initialPos: { x: 500, y: 50 }, initialSize: { w: 400, h: 300 }, icon: Play },
    { id: 'bookmarks', title: 'Bookmarks', type: 'bookmarks', isOpen: false, zIndex: 5, initialPos: { x: 550, y: 80 }, initialSize: { w: 300, h: 400 }, icon: Bookmark },
    { id: 'projects', title: 'Project Manager', type: 'projects', isOpen: false, zIndex: 5, initialPos: { x: 600, y: 100 }, initialSize: { w: 500, h: 400 }, icon: FolderTree },

    // Misc
    { id: 'output', title: 'Console Output', type: 'output', isOpen: true, zIndex: 2, initialPos: { x: 300, y: 800 }, initialSize: { w: 800, h: 200 }, icon: Terminal },
    { id: 'chat', title: 're-Brain-AI', type: 'chat', isOpen: true, zIndex: 10, initialPos: { x: 1100, y: 20 }, initialSize: { w: 320, h: 800 }, icon: Sparkles },
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
      setFiles(data);
    } catch (e) { console.error(e); }
  };

  const toggleWindow = (id: string) => {
    setWindows(prev => prev.map(w => w.id === id ? { ...w, isOpen: !w.isOpen, zIndex: topZ + 1 } : w));
    setTopZ(prev => prev + 1);
  };

  const closeWindow = (id: string) => {
    setWindows(prev => prev.map(w => w.id === id ? { ...w, isOpen: false } : w));
  };

  const focusWindow = (id: string) => {
    setWindows(prev => prev.map(w => w.id === id ? { ...w, zIndex: topZ + 1 } : w));
    setTopZ(prev => prev + 1);
  };

  const onSelectFunction = (func: { name: string, address: string }) => {
    setSelectedFunction(func);
    // Auto-open decompiler and focus it
    setWindows(prev => prev.map(w => {
      if (w.id === 'decompile') return { ...w, isOpen: true, zIndex: topZ + 2 };
      return w;
    }));
    setTopZ(prev => prev + 2);
  };

  const handleUiCommand = (cmd: any) => {
    if (cmd.action === 'SWITCH_TAB') {
      const targetId = cmd.tab;
      // Map AI terms to IDs if needed
      let winId = targetId;
      if (targetId === 'functions') winId = 'symbol_tree';

      setWindows(prev => prev.map(w => {
        if (w.id === winId) return { ...w, isOpen: true, zIndex: topZ + 1 };
        return w;
      }));
      setTopZ(prev => prev + 1);

      if (cmd.file && cmd.file !== activeFile) setActiveFile(cmd.file);
      if (cmd.function && cmd.address) {
        setSelectedFunction({ name: cmd.function, address: cmd.address });
      }
    }

    // Handle goto -> Hex View, Decompiler, Graph, Symbol Tree
    if (cmd.action === 'goto') {
      const addr = cmd.target;
      setSelectedAddress(addr);

      // Open all relevant analysis views
      setWindows(prev => prev.map(w => {
        if (['hex', 'decompile', 'graph', 'symbol_tree'].includes(w.id)) {
          return { ...w, isOpen: true, zIndex: topZ + 1 };
        }
        return w;
      }));
      setTopZ(prev => prev + 1);
    }
  };

  const handleDeleteFile = async (file: string) => {
    if (confirm(`Delete ${file}? This cannot be undone.`)) {
      try {
        await fetch(`http://localhost:8005/binary/${file}`, { method: 'DELETE' });
        if (activeFile === file) {
          setActiveFile(null);
          setSelectedFunction(null);
        }
        fetchFiles();
      } catch (e) {
        console.error(e);
      }
    }
  };

  return (
    <div className="flex h-screen bg-[#1e1e1e] text-zinc-300 font-sans overflow-hidden">
      {/* Launch Bar */}
      <div className="w-12 bg-[#2d2d30] border-r border-[#3e3e42] flex flex-col items-center py-4 gap-3 z-50">
        <div className="mb-4">
          <img
            src="/logoicon.png"
            alt="Logo"
            className="w-8 h-8 object-contain opacity-50 grayscale hover:opacity-100 hover:grayscale-0 transition-all duration-300"
          />
        </div>

        {/* Core Analysis Group */}
        <div className="flex flex-col gap-2 w-full items-center pb-2 border-b border-white/5">
          {windows.filter(w => ['project', 'listing', 'symbol_tree', 'tree', 'datatypes'].includes(w.type)).map(w => (
            <LaunchIcon key={w.id} w={w} toggleWindow={toggleWindow} />
          ))}
        </div>

        {/* Views Group */}
        <div className="flex flex-col gap-2 w-full items-center pb-2 border-b border-white/5">
          {windows.filter(w => ['decompile', 'graph', 'call_tree', 'hex', 'strings'].includes(w.type)).map(w => (
            <LaunchIcon key={w.id} w={w} toggleWindow={toggleWindow} />
          ))}
        </div>

        {/* Tools Group */}
        <div className="flex flex-col gap-2 w-full items-center">
          {windows.filter(w => ['scripts', 'bookmarks', 'projects', 'chat', 'output', 'dashboard'].includes(w.type)).map(w => (
            <LaunchIcon key={w.id} w={w} toggleWindow={toggleWindow} />
          ))}
        </div>

        <div className="mt-auto flex flex-col gap-4">
          <button onClick={() => setShowUpload(true)} className="w-10 h-10 text-zinc-500 hover:text-indigo-400 flex items-center justify-center"><Upload size={20} /></button>
          <button className="w-10 h-10 text-zinc-500 hover:text-zinc-300 flex items-center justify-center"><Settings size={20} /></button>
        </div>
      </div>

      <main className="flex-1 relative overflow-hidden z-10 bg-[#1e1e1e]">
        {/* Workspace Wallpaper */}
        <div
          className="absolute inset-0 z-0 opacity-10 pointer-events-none bg-center bg-no-repeat grayscale"
          style={{ backgroundImage: 'url(/logoicon.png)', backgroundSize: '85%' }}
        />

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
            {win.type === 'listing' && <DisassemblyView file={activeFile} />}
            {win.type === 'symbol_tree' && <SymbolTree file={activeFile} onSelectFunction={onSelectFunction} selectedAddress={selectedAddress} />}
            {win.type === 'datatypes' && <DataTypeManager file={activeFile} />}
            {win.type === 'tree' && <ProgramTree file={activeFile} />}

            {win.type === 'decompile' && activeFile && (selectedFunction || selectedAddress) && (
              <CodeViewer
                file={activeFile}
                address={selectedFunction?.address ?? selectedAddress!}
                functionName={selectedFunction?.name ?? `Loc_${selectedAddress}`}
              />
            )}
            {win.type === 'decompile' && (!activeFile || (!selectedFunction && !selectedAddress)) && <NoFunctionSelected />}

            {win.type === 'graph' && <FunctionGraph file={activeFile} functionAddress={selectedFunction?.address ?? selectedAddress ?? null} />}
            {win.type === 'call_tree' && <CallTree file={activeFile} onSelectFunction={onSelectFunction} />}
            {win.type === 'hex' && activeFile && <HexViewer file={activeFile} address={selectedAddress} />}
            {win.type === 'hex' && !activeFile && <NoFileSelected />}
            {win.type === 'strings' && activeFile && <StringsViewer file={activeFile} />}
            {win.type === 'strings' && !activeFile && <NoFileSelected />}

            {win.type === 'scripts' && <ScriptManager />}
            {win.type === 'bookmarks' && <BookmarkManager file={activeFile} />}
            {win.type === 'projects' && <ProjectManager />}

            {win.type === 'dashboard' && <Dashboard apiStatus={apiStatus} fileCount={files.length} />}
            {win.type === 'output' && <ActivityLog />}

            {win.type === 'chat' && (
              <DockedChat
                apiStatus={apiStatus}
                onApiStatusChange={setApiStatus}
                onCommand={handleUiCommand}
                currentFile={activeFile}
                currentFunction={selectedFunction?.name ?? null}
                currentAddress={selectedFunction?.address ?? null}
              />
            )}
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

function LaunchIcon({ w, toggleWindow }: { w: WindowState, toggleWindow: (id: string) => void }) {
  return (
    <button
      onClick={() => toggleWindow(w.id)}
      className={`w-8 h-8 rounded flex items-center justify-center transition-all duration-200 group relative ${w.isOpen ? 'bg-white/10 text-indigo-400' : 'text-zinc-500 hover:bg-white/5 hover:text-zinc-300'}`}
    >
      <w.icon size={18} />
      {w.isOpen && <div className="absolute left-0 w-0.5 h-4 bg-indigo-500 rounded-r-full" />}
      <div className="absolute left-full ml-3 px-2 py-1 bg-[#252526] border border-[#3e3e42] text-white text-[10px] rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50 shadow-lg">
        {w.title}
      </div>
    </button>
  );
}

function NoFileSelected() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 bg-[#0c0c0e]/30 backdrop-blur-sm p-12 text-center">
      <Files size={40} className="mb-4 opacity-20" />
      <p className="italic text-sm">Select a binary from the File Explorer</p>
    </div>
  )
}

function NoFunctionSelected() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 bg-[#0c0c0e]/30 backdrop-blur-sm p-12 text-center">
      <Code size={40} className="mb-4 opacity-20" />
      <p className="italic text-sm">Select a function from the Symbol Tree</p>
    </div>
  )
}

function Dashboard({ apiStatus, fileCount }: { apiStatus: string, fileCount: number }) {
  return (
    <div className="flex-1 p-6 overflow-auto bg-[#1e1e1e]">
      <h2 className="text-xl font-bold mb-6 flex items-center gap-2 text-zinc-200">
        <LayoutDashboard size={20} className="text-indigo-400" />
        Project Dashboard
      </h2>
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-[#252526] p-4 rounded-lg border border-[#3e3e42]">
          <span className="text-[10px] text-zinc-500 uppercase">Binaries</span>
          <p className="text-2xl font-mono text-zinc-200">{fileCount}</p>
        </div>
        <div className="bg-[#252526] p-4 rounded-lg border border-[#3e3e42]">
          <span className="text-[10px] text-zinc-500 uppercase">Status</span>
          <p className={`text-sm font-bold ${apiStatus === 'online' ? 'text-emerald-400' : 'text-red-400'}`}>{apiStatus}</p>
        </div>
      </div>
      <div className="mt-8">
        <h3 className="text-xs font-bold text-zinc-400 mb-4 uppercase tracking-widest">Recent Activity</h3>
        <ActivityLog />
      </div>
    </div>
  );
}


