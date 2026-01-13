'use client';

import { useState, useEffect, useRef } from 'react';
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
import DataTypeViewer from './components/DataTypeViewer';
import CallTree from './components/CallTree';
import ScriptManager from './components/ScriptManager';
import BookmarkManager from './components/BookmarkManager';
import ProjectManager from './components/ProjectManager';
import EmulatorWindow from './components/EmulatorWindow';
import { API_URL } from './utils';

import {
  Code, Sparkles, Terminal, Files, Search, Settings, Box,
  FolderTree, GitGraph, ListTree, LayoutDashboard, Binary, FileCode, Type, Upload, X,
  AlignLeft, Database, GitCommit, Play, Bookmark, Cpu
} from 'lucide-react';

interface WindowState {
  id: string;
  title: string;
  type: 'project' | 'chat' | 'hex' | 'symbol_tree' | 'decompile' | 'strings' | 'dashboard' | 'output' | 'tree' | 'graph' | 'listing' | 'datatypes' | 'call_tree' | 'scripts' | 'bookmarks' | 'projects' | 'emulator' | 'datatype_preview';
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
  const [chatMessage, setChatMessage] = useState<{ role: 'user' | 'assistant' | 'system', content: string } | null>(null);
  const [selectedDataType, setSelectedDataType] = useState<{ name: string, path: string } | null>(null);

  // Window Z-Index Tracker
  const [topZ, setTopZ] = useState(10);
  const [viewport, setViewport] = useState({ w: 1200, h: 800 });
  const lastViewport = useRef({ w: 1200, h: 800 });

  // Define windows without initializing state yet to use viewport values
  const getInitialWindows = (vw: number, vh: number): WindowState[] => [
    { id: 'project', title: 'File Explorer', type: 'project', isOpen: true, zIndex: 1, initialPos: { x: 60, y: 20 }, initialSize: { w: Math.min(260, vw * 0.2), h: vh * 0.7 }, icon: Files },
    { id: 'dashboard', title: 'System Overview', type: 'dashboard', isOpen: true, zIndex: 0, initialPos: { x: vw * 0.28, y: 20 }, initialSize: { w: Math.min(800, vw * 0.6), h: vh * 0.6 }, icon: LayoutDashboard },
    { id: 'listing', title: 'Listing View', type: 'listing', isOpen: false, zIndex: 2, initialPos: { x: vw * 0.28, y: vh * 0.65 }, initialSize: { w: Math.min(800, vw * 0.6), h: vh * 0.3 }, icon: AlignLeft },
    { id: 'symbol_tree', title: 'Symbol Tree', type: 'symbol_tree', isOpen: false, zIndex: 3, initialPos: { x: vw - 340, y: 20 }, initialSize: { w: 300, h: vh * 0.45 }, icon: ListTree },
    { id: 'datatypes', title: 'Data Type Manager', type: 'datatypes', isOpen: false, zIndex: 3, initialPos: { x: vw - 340, y: vh * 0.5 }, initialSize: { w: 300, h: vh * 0.45 }, icon: Database },
    { id: 'datatype_preview', title: 'Data Type Preview', type: 'datatype_preview', isOpen: false, zIndex: 6, initialPos: { x: vw * 0.45, y: vh * 0.25 }, initialSize: { w: 500, h: 400 }, icon: FileCode },
    { id: 'tree', title: 'Program Tree', type: 'tree', isOpen: false, zIndex: 3, initialPos: { x: vw * 0.28, y: 20 }, initialSize: { w: 300, h: vh * 0.45 }, icon: FolderTree },
    { id: 'decompile', title: 'Decompiler', type: 'decompile', isOpen: false, zIndex: 4, initialPos: { x: vw * 0.4, y: 20 }, initialSize: { w: vw * 0.4, h: vh * 0.6 }, icon: Code },
    { id: 'graph', title: 'Function Graph', type: 'graph', isOpen: false, zIndex: 4, initialPos: { x: vw * 0.35, y: vh * 0.1 }, initialSize: { w: vw * 0.5, h: vh * 0.6 }, icon: GitGraph },
    { id: 'call_tree', title: 'Function Call Tree', type: 'call_tree', isOpen: false, zIndex: 4, initialPos: { x: vw * 0.38, y: vh * 0.15 }, initialSize: { w: vw * 0.3, h: vh * 0.6 }, icon: GitCommit },
    { id: 'emulator', title: 'P-Code Emulator', type: 'emulator', isOpen: false, zIndex: 5, initialPos: { x: vw * 0.4, y: vh * 0.6 }, initialSize: { w: 500, h: 400 }, icon: Cpu },
    { id: 'hex', title: 'Bytes', type: 'hex', isOpen: false, zIndex: 3, initialPos: { x: vw * 0.35, y: vh * 0.6 }, initialSize: { w: vw * 0.5, h: vh * 0.35 }, icon: Binary },
    { id: 'strings', title: 'Defined Strings', type: 'strings', isOpen: false, zIndex: 3, initialPos: { x: vw * 0.4, y: vh * 0.2 }, initialSize: { w: vw * 0.4, h: vh * 0.5 }, icon: Type },
    { id: 'scripts', title: 'Script Manager', type: 'scripts', isOpen: false, zIndex: 5, initialPos: { x: vw * 0.45, y: vh * 0.1 }, initialSize: { w: 400, h: 300 }, icon: Play },
    { id: 'bookmarks', title: 'Bookmarks', type: 'bookmarks', isOpen: false, zIndex: 5, initialPos: { x: vw * 0.5, y: vh * 0.15 }, initialSize: { w: 300, h: 400 }, icon: Bookmark },
    { id: 'projects', title: 'Project Manager', type: 'projects', isOpen: false, zIndex: 5, initialPos: { x: vw * 0.55, y: vh * 0.2 }, initialSize: { w: 500, h: 400 }, icon: FolderTree },
    { id: 'output', title: 'Console Output', type: 'output', isOpen: true, zIndex: 2, initialPos: { x: vw * 0.28, y: vh - 220 }, initialSize: { w: vw * 0.6, h: 200 }, icon: Terminal },
    { id: 'chat', title: 're-Brain-AI', type: 'chat', isOpen: true, zIndex: 10, initialPos: { x: vw - 360, y: 20 }, initialSize: { w: 320, h: vh - 40 }, icon: Sparkles },
  ];

  const [windows, setWindows] = useState<WindowState[]>([]);

  // Initialize and handle resize
  useEffect(() => {
    const nw = window.innerWidth;
    const nh = window.innerHeight;
    lastViewport.current = { w: nw, h: nh };
    setViewport({ w: nw, h: nh });
    setWindows(getInitialWindows(nw, nh));

    const handleResize = () => {
      const vnw = window.innerWidth;
      const vnh = window.innerHeight;

      setWindows(prev => {
        if (prev.length === 0) return getInitialWindows(vnw, vnh);

        // Scale existing windows relative to the LAST viewport
        const rw = vnw / lastViewport.current.w;
        const rh = vnh / lastViewport.current.h;

        return prev.map(w => ({
          ...w,
          initialPos: {
            x: Math.max(48, Math.min(w.initialPos.x * rw, vnw - 100)),
            y: Math.max(0, Math.min(w.initialPos.y * rh, vnh - 50))
          },
          initialSize: {
            w: Math.max(300, Math.min(w.initialSize.w * rw, vnw - 48)),
            h: Math.max(200, Math.min(w.initialSize.h * rh, vnh))
          }
        }));
      });

      lastViewport.current = { w: vnw, h: vnh };
      setViewport({ w: vnw, h: vnh });
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    fetchFiles();
    const interval = setInterval(fetchFiles, 5000);
    return () => clearInterval(interval);
  }, []);

  // const API_URL = ... (removed local declaration)

  const fetchFiles = async () => {
    try {
      const res = await fetch(`${API_URL}/binaries`);
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



  const handleSelectType = (name: string, path: string) => {
    setSelectedDataType({ name, path });
    // Open preview window
    const win = windows.find(w => w.id === 'datatype_preview');
    if (win && !win.isOpen) {
      toggleWindow('datatype_preview');
      focusWindow('datatype_preview');
    } else {
      focusWindow('datatype_preview');
    }
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

    if (cmd.action === 'emulate') {
      if (!activeFile) return;

      // 1. Open Window (User Feedback)
      setWindows(prev => prev.map(w => {
        if (w.id === 'emulator') return { ...w, isOpen: true, zIndex: topZ + 1 };
        return w;
      }));
      setTopZ(prev => prev + 1);
      if (cmd.address) setSelectedAddress(cmd.address);

      // 2. Run Emulation (AI Feedback Loop)
      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/emulate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            address: cmd.address,
            steps: cmd.steps || 5,
            stop_at: cmd.stop_at
          })
        }).then(r => r.json()).then(data => {
          // Construct feedback string for AI
          let feedback = `Emulation Results for ${cmd.steps} steps at ${cmd.address}:\n`;
          if (Array.isArray(data)) {
            const lastStep = data[data.length - 1];
            const registers = lastStep.registers || {};
            const regStr = Object.entries(registers).map(([k, v]) => `${k}=${v}`).join(", ");

            if (lastStep.error && lastStep.error.includes("Breakpoint")) {
              feedback += `BREAKPOINT HIT at ${lastStep.address} (${lastStep.instruction}).\nRegisters: ${regStr}`;
            } else {
              feedback += `Stopped at ${lastStep.address} (${lastStep.instruction}).\nRegisters: ${regStr}`;
            }
          } else if (data.error) {
            feedback += `Error: ${data.error}`;
          }
          resolve(feedback);
        }).catch(e => {
          resolve(`Emulation failed: ${e}`);
        });
      });
    }

    if (cmd.action === 'batch_analysis') {
      if (!activeFile) return "No active file selected.";

      // Notify user via chat feedback that it started
      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/batch_analysis`, {
          method: 'POST'
        }).then(r => r.json()).then(data => {
          if (data.error) {
            resolve(`Batch Analysis Failed: ${data.error}`);
          } else {
            const findingsCount = data.findings ? data.findings.length : 0;
            let report = `Batch Analysis Complete.\nScanned ${data.total_functions} functions.\nFound ${findingsCount} items of interest.\n\n`;
            if (data.findings && data.findings.length > 0) {
              data.findings.forEach((f: any) => {
                report += `- [${f.category}] ${f.function}: ${f.details}\n`;
              });
            }
            resolve(report);
          }
        }).catch(e => {
          resolve(`Batch Analysis Request Failed: ${e}`);
        });
      });
    }

    if (cmd.action === 'memory_analysis') {
      if (!activeFile) return "No active file selected.";

      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/memory_analysis`, {
          method: 'POST'
        }).then(r => r.json()).then(data => {
          if (data.error) {
            resolve(`Memory Analysis Failed: ${data.error}`);
          } else {
            resolve(`Memory Analysis Complete.\n\n${data.analysis}`);
          }
        }).catch(e => {
          resolve(`Memory Analysis Request Failed: ${e}`);
        });
      });
    }

    if (cmd.action === 'cipher_analysis') {
      if (!activeFile) return "No active file selected.";

      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/cipher_analysis`, {
          method: 'POST'
        }).then(r => r.json()).then(data => {
          if (data.error) {
            resolve(`Cipher Analysis Failed: ${data.error}`);
          } else {
            const findingsCount = data.findings ? data.findings.length : 0;
            let report = `Cipher Analysis Complete.\nFound ${findingsCount} suspicious functions.\n\nAI Analysis:\n${data.analysis}\n\n`;
            if (data.findings && data.findings.length > 0) {
              report += "Top Suspicious Functions:\n";
              data.findings.forEach((f: any) => {
                report += `- ${f.name} (${f.address}): Score ${f.score} (Bitwise Ratio: ${(f.ratio * 100).toFixed(1)}%)\n`;
              });
            }
            resolve(report);
          }
        }).catch(e => {
          resolve(`Cipher Analysis Request Failed: ${e}`);
        });
      });
    }

    if (cmd.action === 'malware_analysis') {
      if (!activeFile) return "No active file selected.";

      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/malware_analysis`, { method: 'POST' })
          .then(r => r.json())
          .then(data => {
            if (data.error) {
              resolve(`Malware Scan Failed: ${data.error}`);
            } else {
              let report = `Malware Scan Complete.\nAnalysis: ${data.analysis}\n`;
              if (data.findings) {
                const impCount = data.findings.imports ? data.findings.imports.length : 0;
                const strCount = data.findings.strings ? data.findings.strings.length : 0;
                if (impCount > 0 || strCount > 0) {
                  report += `\nSuspicious Imports: ${impCount}\nSuspicious Strings: ${strCount}`;
                }
              }
              resolve(report);
            }
          })
          .catch(e => resolve(`Malware Scan Request Failed: ${e}`));
      });
    }

    if (cmd.action === 'rename') {
      if (!activeFile) return;
      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/rename`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: cmd.target, new_name: cmd.new_name })
        }).then(r => r.json()).then(data => {
          if (data.status === 'success') {
            resolve(`SUCCESS: Renamed ${data.old_name} to ${data.new_name}.\nRefresh the Symbol Tree to see changes.`);
          } else {
            resolve(`RENAME FAILED: ${data.error}`);
          }
        }).catch(e => resolve(`Rename Request Failed: ${e}`));
      });
    }

    if (cmd.action === 'comment') {
      if (!activeFile) return;
      return new Promise<string>((resolve) => {
        fetch(`${API_URL}/binary/${activeFile}/comment`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ address: cmd.address, comment: cmd.comment, type: cmd.type })
        }).then(r => r.json()).then(data => {
          if (data.status === 'success') {
            resolve(`SUCCESS: Set ${cmd.type || 'plate'} comment at ${cmd.address}.`);
          } else {
            resolve(`COMMENT FAILED: ${data.error}`);
          }
        }).catch(e => resolve(`Comment Request Failed: ${e}`));
      });
    }
  };

  // Analysis Tools Integration
  interface Tool {
    name: string;
    action: string;
    icon: any;
    color: string;
  }
  const [confirmTool, setConfirmTool] = useState<Tool | null>(null);

  const handleRunTool = (tool: Tool) => {
    console.log("handleRunTool called with:", tool);
    setConfirmTool(tool);
  };

  const executeTool = async () => {
    if (!confirmTool) return;
    console.log("executeTool called for:", confirmTool);
    const action = confirmTool.action;
    setConfirmTool(null);
    const result = await handleUiCommand({ action: action });
    if (result && typeof result === 'string') {
      setChatMessage({ role: 'system', content: result });
    }
  };

  const handleDeleteFile = async (file: string) => {
    if (confirm(`Delete ${file}? This cannot be undone.`)) {
      try {
        await fetch(`${API_URL}/binary/${file}`, { method: 'DELETE' });
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
          {windows.filter(w => ['scripts', 'bookmarks', 'projects', 'emulator', 'chat', 'output', 'dashboard'].includes(w.type)).map(w => (
            <LaunchIcon key={w.id} w={w} toggleWindow={toggleWindow} />
          ))}
        </div>
      </div>

      <main className="flex-1 relative overflow-hidden z-10 bg-[#1e1e1e]">
        {/* Wallpaper */}
        <div
          className="absolute inset-0 z-0 opacity-10 pointer-events-none bg-center bg-no-repeat grayscale"
          style={{ backgroundImage: 'url(/logoicon.png)', backgroundSize: '85%' }}
        />

        {windows.map((win) => win.isOpen && (
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
            onClick={() => focusWindow(win.id)}
          >
            {win.type === 'project' && (
              <ProjectExplorer
                files={files} activeFile={activeFile}
                setActiveFile={(f) => { setActiveFile(f); setSelectedFunction(null); }}
                onUploadClick={() => setShowUpload(true)}
                onDeleteFile={handleDeleteFile}
                onRunTool={handleRunTool}
              />
            )}
            {win.type === 'listing' && <DisassemblyView file={activeFile || ''} address={selectedAddress} />}
            {win.type === 'symbol_tree' && <SymbolTree file={activeFile || ''} onSelectFunction={onSelectFunction} selectedAddress={selectedAddress} />}
            {win.type === 'datatypes' && <DataTypeManager file={activeFile || ''} onSelectType={handleSelectType} />}
            {win.type === 'tree' && <ProgramTree file={activeFile || ''} />}

            {win.type === 'decompile' && activeFile && (selectedFunction || selectedAddress) && (
              <CodeViewer
                file={activeFile}
                address={selectedFunction?.address ?? selectedAddress!}
                functionName={selectedFunction?.name ?? `Loc_${selectedAddress}`}
              />
            )}
            {win.type === 'decompile' && (!activeFile || (!selectedFunction && !selectedAddress)) && (
              <div className="flex-1 flex flex-col items-center justify-center text-zinc-600">
                <Code size={48} className="mb-4 opacity-20" />
                <p>Select a function to decompile</p>
              </div>
            )}

            {win.type === 'datatype_preview' && activeFile && selectedDataType && (
              <DataTypeViewer file={activeFile} typeName={selectedDataType.name} typePath={selectedDataType.path} />
            )}

            {win.type === 'graph' && <FunctionGraph file={activeFile || ''} functionAddress={selectedFunction?.address || null} />}
            {win.type === 'call_tree' && <CallTree file={activeFile || ''} functionName={selectedFunction?.name} />}
            {win.type === 'hex' && activeFile && <HexViewer file={activeFile} address={selectedAddress} />}
            {win.type === 'hex' && !activeFile && <NoFileSelected />}
            {win.type === 'strings' && activeFile && <StringsViewer file={activeFile} onAddressClick={(addr) => handleUiCommand({ action: 'goto', target: addr })} />}
            {win.type === 'strings' && !activeFile && <NoFileSelected />}

            {win.type === 'scripts' && <ScriptManager />}
            {win.type === 'bookmarks' && <BookmarkManager file={activeFile || ''} onNavigate={(addr) => handleUiCommand({ action: 'goto', target: addr })} />}
            {win.type === 'projects' && <ProjectManager activeProject="re-Brain" onProjectChange={() => { }} />}
            {win.type === 'emulator' && <EmulatorWindow file={activeFile || ''} address={selectedAddress || ''} onStop={() => { }} />}

            {win.type === 'dashboard' && <ActivityLog logs={[]} />}
            {win.type === 'output' && <ActivityLog logs={[]} />}

            {win.type === 'chat' && (
              <DockedChat
                apiStatus={apiStatus}
                onApiStatusChange={setApiStatus}
                onCommand={handleUiCommand}
                currentFile={activeFile}
                currentFunction={selectedFunction?.name ?? null}
                currentAddress={selectedFunction?.address ?? null}
                incomingMessage={chatMessage}
                onMessageConsumed={() => setChatMessage(null)}
              />
            )}
          </WindowFrame>
        ))}

        {/* Upload Modal */}
        {showUpload && (
          <div className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-md flex items-center justify-center p-4">
            <FileUpload onClose={() => setShowUpload(false)} onUploadComplete={() => { setShowUpload(false); fetchFiles(); }} />
          </div>
        )}

        {/* Confirmation Modal */}
        {confirmTool && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
            <div className="bg-[#1e1e20] border border-white/10 rounded-lg shadow-2xl w-96 p-6 transform scale-100 animate-in zoom-in-95 duration-200">
              <div className="flex flex-col items-center text-center space-y-4">
                <div className={`p-3 rounded-full bg-opacity-10 ${confirmTool.color.replace('text-', 'bg-')}`}>
                  <confirmTool.icon size={32} className={confirmTool.color} />
                </div>

                <div>
                  <h3 className="text-lg font-bold text-white">Run {confirmTool.name}?</h3>
                  <p className="text-sm text-zinc-400 mt-2">
                    This process uses AI to analyze the binary and may take a few minutes.
                    Results will be saved to the Knowledge Base.
                  </p>
                </div>

                <div className="flex items-center gap-3 w-full mt-2">
                  <button
                    onClick={() => setConfirmTool(null)}
                    className="flex-1 px-4 py-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors text-sm font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={executeTool}
                    className="flex-1 px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-500 text-white transition-colors text-sm font-bold flex items-center justify-center gap-2"
                  >
                    <Play size={14} className="fill-current" />
                    Run Analysis
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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


