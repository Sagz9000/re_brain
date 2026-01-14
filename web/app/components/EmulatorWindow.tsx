import { useState, useEffect } from 'react';
import { Play, RotateCcw, Cpu, AlertCircle, ArrowRight } from 'lucide-react';
import { API_URL } from '../utils';

interface EmulatorProps {
    file: string | null;
    address?: string | null;
    onStop?: () => void;
}

interface Step {
    address: string;
    instruction: string;
    registers: Record<string, string>;
    error?: string;
}

export default function EmulatorWindow({ file, address: initialAddress, onStop }: EmulatorProps) {
    const [address, setAddress] = useState(initialAddress || '');
    const [steps, setSteps] = useState(5);
    const [trace, setTrace] = useState<Step[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (initialAddress) setAddress(initialAddress);
    }, [initialAddress]);

    const handleRun = async () => {
        if (!file || !address) return;
        setLoading(true);
        setError(null);
        setTrace([]); // Clear previous

        try {
            const res = await fetch(`${API_URL}/binary/${file}/emulate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ address, steps })
            });
            const data = await res.json();

            if (data.error) {
                setError(data.error);
            } else if (Array.isArray(data)) {
                setTrace(data);
            } else {
                setError("Unexpected response format");
            }
        } catch (e: any) {
            setError(e.message || "Emulation failed");
        } finally {
            setLoading(false);
        }
    };

    if (!file) {
        return (
            <div className="flex flex-col items-center justify-center h-full text-zinc-500 gap-2">
                <Cpu size={24} className="opacity-20" />
                <span className="text-xs">Select a binary to emulate</span>
            </div>
        );
    }

    // Helper to get changed registers formatting
    const getRegDiff = (stepIndex: number, regs: Record<string, string>) => {
        return Object.entries(regs).map(([k, v]) => (
            <span key={k} className="mr-2 inline-flex items-center gap-1 bg-white/5 px-1 rounded text-[10px] text-indigo-300">
                <span className="font-bold text-zinc-500">{k}:</span>
                <span className="font-mono">{v}</span>
            </span>
        ));
    };

    return (
        <div className="flex flex-col h-full bg-[#1e1e1e] text-sm">
            {/* Toolbar */}
            <div className="flex items-center gap-2 p-2 border-b border-white/5 bg-[#252526]">
                <div className="flex items-center gap-1 bg-black/20 rounded px-2 py-1 border border-white/5">
                    <span className="text-[10px] text-zinc-500 font-mono">ADDR:</span>
                    <input
                        type="text"
                        value={address}
                        onChange={e => setAddress(e.target.value)}
                        className="bg-transparent border-none focus:outline-none w-24 font-mono text-zinc-200 text-xs"
                        placeholder="0x..."
                    />
                </div>
                <div className="flex items-center gap-1 bg-black/20 rounded px-2 py-1 border border-white/5">
                    <span className="text-[10px] text-zinc-500 font-mono">STEPS:</span>
                    <input
                        type="number"
                        value={steps}
                        onChange={e => setSteps(Number(e.target.value))}
                        className="bg-transparent border-none focus:outline-none w-12 font-mono text-zinc-200 text-xs"
                        min={1}
                        max={50}
                    />
                </div>
                <button
                    onClick={handleRun}
                    disabled={loading || !address}
                    className="flex items-center gap-1 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs transition-colors disabled:opacity-50 ml-auto"
                >
                    {loading ? <RotateCcw size={12} className="animate-spin" /> : <Play size={12} fill="currentColor" />}
                    Emulate
                </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-2 scrollbar-thin scrollbar-thumb-zinc-800">
                {error && (
                    <div className="p-3 mb-2 bg-red-500/10 border border-red-500/20 text-red-400 rounded flex items-center gap-2">
                        <AlertCircle size={14} />
                        {error}
                    </div>
                )}

                {trace.length > 0 && (
                    <div className="flex flex-col gap-1">
                        {trace.map((step, i) => (
                            <div key={i} className="flex gap-2 group relative">
                                {/* Left: Step Num */}
                                <div className="w-8 pt-0.5 text-right font-mono text-[10px] text-zinc-600 shrink-0">
                                    {String(i + 1).padStart(2, '0')}
                                </div>

                                {/* Right: Content */}
                                <div className="flex-1 bg-[#2b2b2e] rounded border border-white/5 p-2 font-mono text-xs hover:border-indigo-500/30 transition-colors">
                                    <div className="flex items-center justify-between border-b border-white/5 pb-1 mb-1">
                                        <span className="text-emerald-400">{step.address}</span>
                                        <span className="text-zinc-300 font-bold">{step.instruction}</span>
                                    </div>

                                    {step.error ? (
                                        <div className="text-red-400 text-[10px] mt-1 flex items-center gap-1">
                                            <AlertCircle size={10} /> {step.error}
                                        </div>
                                    ) : (
                                        <div className="flex flex-wrap gap-y-1 mt-1">
                                            {step.registers && Object.keys(step.registers).length > 0 ? (
                                                getRegDiff(i, step.registers)
                                            ) : (
                                                <span className="text-zinc-600 text-[10px] italic">No major register changes tracked</span>
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Connecting Line (visual flair) */}
                                {i < trace.length - 1 && (
                                    <div className="absolute left-[1.15rem] top-8 bottom-[-8px] w-px bg-white/5 group-hover:bg-indigo-500/20" />
                                )}
                            </div>
                        ))}
                    </div>
                )}

                {!loading && trace.length === 0 && !error && (
                    <div className="flex flex-col items-center justify-center h-full text-zinc-600 opacity-50">
                        <Cpu size={32} />
                        <span className="mt-2 text-xs">Ready to emulate P-Code execution</span>
                    </div>
                )}
            </div>
        </div>
    );
}
