'use client';

import { useState } from 'react';
import Header from './components/Header';
import GhidraPanel from './components/GhidraPanel';
import ChatPanel from './components/ChatPanel';
import FileUpload from './components/FileUpload';
import ActivityLog from './components/ActivityLog';

export default function Home() {
  const [apiStatus, setApiStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [showUpload, setShowUpload] = useState(false);

  const handleFeatureClick = (feature: string) => {
    console.log(`[UI] Feature clicked: ${feature}`);
    // Future implementation for feature toggles
    if (feature === 'Upload') {
      setShowUpload(true);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-[#050505] text-zinc-100 font-sans overflow-hidden selection:bg-indigo-500/30 relative">

      <Header apiStatus={apiStatus} onFeatureClick={handleFeatureClick} />

      {/* Main Layout */}
      <div className="flex-1 flex pt-16 h-full relative z-0"> {/* pt-16 to account for fixed header */}
        <GhidraPanel />
        <ChatPanel apiStatus={apiStatus} onApiStatusChange={setApiStatus} />
      </div>

      <ActivityLog />

      {/* Upload Modal Overlay */}
      {showUpload && (
        <div className="absolute inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative w-full max-w-md">
            <button
              onClick={() => setShowUpload(false)}
              className="absolute -top-10 right-0 text-white/50 hover:text-white"
            >
              Close
            </button>
            <FileUpload onUploadComplete={() => { }} />
          </div>
        </div>
      )}

    </div>
  );
}
