'use client';

import { useState, useEffect } from 'react';
import ProjectExplorer from './components/ProjectExplorer';
import DockedChat from './components/DockedChat';
import HexViewer from './components/HexViewer';
import FunctionTable from './components/FunctionTable';
import FileUpload from './components/FileUpload';
import ActivityLog from './components/ActivityLog';
import GhidraPanel from './components/GhidraPanel';
import { Upload, X, Binary, FileCode, LayoutDashboard } from 'lucide-react';

export default function Home() {
  const [apiStatus, setApiStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Workspace State
  const [files, setFiles] = useState<string[]>([]);
  const [activeFile, setActiveFile] = useState<string | null>(null);

  // UI State
  const [activeTab, setActiveTab] = useState<'dashboard' | 'hex' | 'functions'>('dashboard');
  const [showUpload, setShowUpload] = useState(false);

  // Initial Data Fetch
  useEffect(() => {
    fetchFiles();
    const interval = setInterval(fetchFiles, 5000);
    return () => clearInterval(interval);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchFiles = async () => {
    try {
      const res = await fetch('http://localhost:8005/binaries');
      const data = await res.json();
      if (Array.isArray(data)) setFiles(data);
    } catch (e) { console.error(e) }
  };

  const handleUploadComplete = () => {
    setShowUpload(false);
    fetchFiles();
  };

  const handleDeleteFile = async (file: string) => {
    if (!confirm(`Are you sure you want to delete ${file}?`)) return;
    try {
      await fetch(`http://localhost:8005/binary/${file}`, { method: 'DELETE' });
      if (activeFile === file) setActiveFile(null);
      // fetchFiles will handle list update on next tick or immediate call
      fetchFiles();
    } catch (e) {
      alert("Failed to delete file");
    }
  };

  return (
    <div className="flex h-full bg-[#050505] text-zinc-100 font-sans overflow-hidden">

      {/* LEFT: Project Explorer */}
      <ProjectExplorer
        files={files}
        activeFile={activeFile}
        setActiveFile={setActiveFile}
        onUploadClick={() => setShowUpload(true)}
        onDeleteFile={handleDeleteFile}
      />

      {/* CENTER: Work Area */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#0c0c0e]">

        {/* Tab Bar */}
        <div className="flex items-center h-9 bg-[#09090b] border-b border-white/5 px-2 gap-1 overflow-x-auto select-none">
          {/* Dashboard Tab */}
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center gap-2 px-3 h-full text-xs border-r border-white/5 transition-colors ${activeTab === 'dashboard' ? 'bg-[#0c0c0e] text-indigo-400 border-t-2 border-t-indigo-500' : 'text-zinc-500 hover:bg-white/5 hover:text-zinc-300'}`}
          >
            <LayoutDashboard size={14} />
            <span>Dashboard</span>
          </button>

          {/* Dynamic Tool Tabs (only enabled if file selected) */}
          <button
            onClick={() => activeFile && setActiveTab('hex')}
            disabled={!activeFile}
            className={`flex items-center gap-2 px-3 h-full text-xs border-r border-white/5 transition-colors ${activeTab === 'hex' ? 'bg-[#0c0c0e] text-indigo-400 border-t-2 border-t-indigo-500' : 'text-zinc-500 hover:bg-white/5 hover:text-zinc-300 disabled:opacity-30 disabled:cursor-default'}`}
          >
            <Binary size={14} />
            <span>Hex View {activeFile ? `[${activeFile}]` : ''}</span>
          </button>

          <button
            onClick={() => activeFile && setActiveTab('functions')}
            disabled={!activeFile}
            className={`flex items-center gap-2 px-3 h-full text-xs border-r border-white/5 transition-colors ${activeTab === 'functions' ? 'bg-[#0c0c0e] text-indigo-400 border-t-2 border-t-indigo-500' : 'text-zinc-500 hover:bg-white/5 hover:text-zinc-300 disabled:opacity-30 disabled:cursor-default'}`}
          >
            <FileCode size={14} />
            <span>Functions {activeFile ? `[${activeFile}]` : ''}</span>
          </button>
        </div>

        {/* View Content */}
        <div className="flex-1 relative overflow-hidden flex flex-col">
          {activeTab === 'dashboard' && (
            <div className="flex-1 flex flex-col">
              <GhidraPanel />
              {/* Console Output Area */}
              <div className="h-64 border-t border-white/5 bg-[#09090b] flex flex-col">
                <div className="px-3 py-1 bg-[#19191b] text-[10px] font-bold text-zinc-400 uppercase tracking-widest border-b border-white/5">
                  Output & System Activity
                </div>
                <div className="flex-1 overflow-hidden">
                  <ActivityLog />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'hex' && activeFile && (
            <HexViewer file={activeFile} />
          )}

          {activeTab === 'functions' && activeFile && (
            <FunctionTable file={activeFile} />
          )}

          {/* Empty State hint */}
          {activeTab !== 'dashboard' && !activeFile && (
            <div className="absolute inset-0 flex items-center justify-center text-zinc-600">
              <div className="text-center">
                <Binary size={48} className="mx-auto mb-4 opacity-20" />
                <p className="text-sm">Select a binary from the explorer to view {activeTab === 'hex' ? 'hex data' : 'functions'}</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* RIGHT: Docked Chat */}
      <DockedChat apiStatus={apiStatus} onApiStatusChange={setApiStatus} />

      {/* Modals */}
      {showUpload && (
        <div className="absolute inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative w-full max-w-md bg-[#09090b] border border-white/10 rounded-lg p-6 shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-sm font-bold text-zinc-200 uppercase tracking-wide">Import Binary</h3>
              <button onClick={() => setShowUpload(false)} className="text-zinc-500 hover:text-white"><X size={16} /></button>
            </div>
            <FileUpload onUploadComplete={handleUploadComplete} />
          </div>
        </div>
      )}

    </div>
  );
}
