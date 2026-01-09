'use client';

import { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import HexViewer from './components/HexViewer';
import FunctionTable from './components/FunctionTable';
import FloatingChat from './components/FloatingChat';
import FileUpload from './components/FileUpload';
import ActivityLog from './components/ActivityLog';
import GhidraPanel from './components/GhidraPanel';
import { Upload } from 'lucide-react';

export default function Home() {
  const [apiStatus, setApiStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [activeView, setActiveView] = useState<'dashboard' | 'hex' | 'functions'>('dashboard');
  const [activeFile, setActiveFile] = useState<string | null>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [showUpload, setShowUpload] = useState(false);

  // Fetch file list on mount
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const res = await fetch('http://localhost:8005/binaries');
        const data = await res.json();
        if (Array.isArray(data)) {
          setFiles(data);
          if (data.length > 0 && !activeFile) {
            setActiveFile(data[0]); // Default to first file
          }
        }
      } catch (e) { console.error(e) }
    };
    fetchFiles();
    // Poll for new files e.g. after upload
    const interval = setInterval(fetchFiles, 5000);
    return () => clearInterval(interval);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleUploadComplete = () => {
    setShowUpload(false);
    // Files will update on next poll
  };

  return (
    <div className="flex h-full bg-[#050505] text-zinc-100 font-sans overflow-hidden">

      {/* Sidebar */}
      <Sidebar
        activeView={activeView}
        setActiveView={setActiveView}
        files={files}
        activeFile={activeFile}
        setActiveFile={setActiveFile}
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 relative">

        {/* View Router */}
        {activeView === 'dashboard' && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <GhidraPanel />
            {/* Empty State / Upload Prompt if no files */}
            {files.length === 0 && (
              <div className="absolute inset-0 flex items-center justify-center bg-black/50 backdrop-blur-sm z-10">
                <div className="text-center">
                  <h3 className="text-xl font-bold mb-2">No Binaries Loaded</h3>
                  <button
                    onClick={() => setShowUpload(true)}
                    className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded-lg text-white transition-colors mx-auto"
                  >
                    <Upload size={16} />
                    Upload Binary
                  </button>
                </div>
              </div>
            )}
            {/* Bottom Activity Log */}
            <div className="h-64 border-t border-white/5 bg-[#09090b]">
              <ActivityLog />
            </div>
          </div>
        )}

        {/* Hex View */}
        {activeView === 'hex' && activeFile && (
          <HexViewer file={activeFile} />
        )}

        {/* Function View */}
        {activeView === 'functions' && activeFile && (
          <FunctionTable file={activeFile} />
        )}

        {/* Empty State for Tools */}
        {(activeView === 'hex' || activeView === 'functions') && !activeFile && (
          <div className="flex-1 flex items-center justify-center text-zinc-500">
            Select a file to view
          </div>
        )}

      </div>

      {/* Floating Chat Bubble */}
      <FloatingChat apiStatus={apiStatus} onApiStatusChange={setApiStatus} />

      {/* Upload Modal */}
      {showUpload && (
        <div className="absolute inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative w-full max-w-md bg-[#09090b] border border-white/10 rounded-2xl p-6 shadow-2xl">
            <button
              onClick={() => setShowUpload(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-white"
            >
              Close
            </button>
            <FileUpload onUploadComplete={handleUploadComplete} />
          </div>
        </div>
      )}

    </div>
  );
}
