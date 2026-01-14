'use client';

import React, { useState, useEffect, useRef } from 'react';

interface DebuggerProps {
    binaryName: string;
    isActive: boolean;
}

export default function Debugger({ binaryName, isActive }: DebuggerProps) {
    const [output, setOutput] = useState<string[]>([]);
    const [registers, setRegisters] = useState<Record<string, string>>({});
    const [memory, setMemory] = useState<string>('');
    const [stack, setStack] = useState<string[]>([]);
    const [status, setStatus] = useState<string>('Idle');

    const [cmdInput, setCmdInput] = useState('');
    const outputRef = useRef<HTMLDivElement>(null);

    // Auto-scroll terminal
    useEffect(() => {
        if (outputRef.current) {
            outputRef.current.scrollTop = outputRef.current.scrollHeight;
        }
    }, [output]);

    const addOutput = (line: string) => {
        setOutput(prev => [...prev, line]);
    };

    const fetchState = async () => {
        try {
            const res = await fetch(`/api/debug/state/${binaryName}`);
            const data = await res.json();
            if (data.active) {
                setRegisters(data.registers || {});
                setStack(data.stack || []);
                setStatus('Active');
            } else {
                setStatus('Inactive');
            }
        } catch (e) {
            console.error(e);
        }
    };

    const sendAction = async (action: string, payload: any = {}) => {
        try {
            setStatus('Busy...');
            const body = { binary_name: binaryName, ...payload };
            const res = await fetch(`/api/debug/${action}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const data = await res.json();

            if (data.output) {
                if (Array.isArray(data.output)) {
                    // pygdbmi format
                    data.output.forEach((o: any) => {
                        if (o.type === 'console' || o.type === 'log') {
                            addOutput(o.payload);
                        }
                    });
                } else {
                    addOutput(JSON.stringify(data.output));
                }
            }

            await fetchState();
        } catch (e) {
            addOutput(`Error: ${e}`);
        }
    };

    const handleCmd = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!cmdInput) return;
        addOutput(`> ${cmdInput}\n`);
        await sendAction('cmd', { command: cmdInput });
        setCmdInput('');
    };

    if (!isActive) return <div className="p-4 text-gray-500">Debugger not active. Select a binary first.</div>;

    return (
        <div className="flex flex-col h-full bg-gray-900 text-green-400 font-mono text-sm">
            {/* Toolbar */}
            <div className="flex gap-2 p-2 bg-gray-800 border-b border-gray-700">
                <button onClick={() => sendAction('start')} className="px-3 py-1 bg-green-700 hover:bg-green-600 rounded">Start</button>
                <button onClick={() => sendAction('step')} className="px-3 py-1 bg-blue-700 hover:bg-blue-600 rounded">Step Into</button>
                <button onClick={() => sendAction('next')} className="px-3 py-1 bg-blue-700 hover:bg-blue-600 rounded">Step Over</button>
                <button onClick={() => sendAction('continue')} className="px-3 py-1 bg-yellow-700 hover:bg-yellow-600 rounded">Continue</button>
                <button onClick={() => sendAction('stop')} className="px-3 py-1 bg-red-700 hover:bg-red-600 rounded">Stop</button>
                <span className="ml-auto flex items-center">{status}</span>
            </div>

            {/* Main Grid */}
            <div className="flex-1 grid grid-cols-3 gap-0 min-h-0">

                {/* Left: Registers */}
                <div className="col-span-1 border-r border-gray-700 flex flex-col">
                    <div className="bg-gray-800 px-2 py-1 font-bold text-gray-300">Registers</div>
                    <div className="flex-1 overflow-auto p-2">
                        <table className="w-full">
                            <tbody>
                                {Object.entries(registers).map(([reg, val]) => (
                                    <tr key={reg}>
                                        <td className="text-blue-300 pr-2">{reg}</td>
                                        <td>{val}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Center: Memory/Stack (Tabs?) - For now just Stack */}
                <div className="col-span-1 border-r border-gray-700 flex flex-col">
                    <div className="bg-gray-800 px-2 py-1 font-bold text-gray-300">Stack</div>
                    <div className="flex-1 overflow-auto p-2 whitespace-pre">
                        {stack.map((line, i) => (
                            <div key={i}>{line}</div>
                        ))}
                    </div>
                </div>

                {/* Right: Terminal */}
                <div className="col-span-1 flex flex-col">
                    <div className="bg-gray-800 px-2 py-1 font-bold text-gray-300">Console</div>
                    <div ref={outputRef} className="flex-1 overflow-auto p-2 whitespace-pre-wrap">
                        {output.map((line, i) => (
                            <span key={i}>{line}</span>
                        ))}
                    </div>
                    <form onSubmit={handleCmd} className="p-2 border-t border-gray-700 flex">
                        <span className="mr-2">$</span>
                        <input
                            type="text"
                            value={cmdInput}
                            onChange={e => setCmdInput(e.target.value)}
                            className="flex-1 bg-transparent outline-none text-white"
                        />
                    </form>
                </div>

            </div>
        </div>
    );
}
