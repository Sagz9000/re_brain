import React, { useState, useEffect } from 'react';

interface SettingsModalProps {
    isOpen: boolean;
    onClose: () => void;
}

export default function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
    const [geminiKey, setGeminiKey] = useState('');
    const [ollamaHost, setOllamaHost] = useState('');
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState('');

    const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8005';


    useEffect(() => {
        if (isOpen) {
            fetchConfig();
        }
    }, [isOpen]);

    const fetchConfig = async () => {
        try {
            const res = await fetch(`${API_URL}/config`);
            const data = await res.json();
            if (data.gemini_key) setGeminiKey(data.gemini_key);
            if (data.ollama_host) setOllamaHost(data.ollama_host);
        } catch (e) {
            console.error("Failed to fetch config", e);
        }
    };

    const handleSave = async () => {
        setLoading(true);
        try {
            await fetch(`${API_URL}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    gemini_key: geminiKey,
                    ollama_host: ollamaHost
                })
            });
            setStatus('Saved!');
            setTimeout(() => {
                setStatus('');
                onClose();
            }, 1000);
        } catch (e: any) {
            console.error("Settings Save Error:", e);
            setStatus('Error: ' + (e.message || 'Unknown save error'));

        } finally {
            setLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 backdrop-blur-sm">
            <div className="bg-[#1e1e1e] border border-white/10 p-6 rounded-lg w-full max-w-md shadow-2xl">
                <h2 className="text-xl font-bold mb-4 text-blue-400">Settings</h2>

                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium mb-1 text-gray-300">Google Gemini API Key</label>
                        <input
                            type="password"
                            value={geminiKey}
                            onChange={(e) => setGeminiKey(e.target.value)}
                            placeholder="AIzaSy..."
                            className="w-full bg-black/30 border border-white/10 rounded p-2 text-white focus:border-blue-500 focus:outline-none"
                        />
                        <p className="text-xs text-gray-500 mt-1">Required for Gemini models. Stored locally.</p>
                    </div>

                    <div>
                        <label className="block text-sm font-medium mb-1 text-gray-300">Ollama Host URL</label>
                        <input
                            type="text"
                            value={ollamaHost}
                            onChange={(e) => setOllamaHost(e.target.value)}
                            placeholder="http://re-ai:11434"
                            className="w-full bg-black/30 border border-white/10 rounded p-2 text-white focus:border-blue-500 focus:outline-none"
                        />
                        <p className="text-xs text-gray-500 mt-1">Override default internal Docker hostname.</p>
                    </div>

                    {status && (
                        <div className={`text-sm ${status.includes('Error') ? 'text-red-400' : 'text-green-400'} text-center`}>
                            {status}
                        </div>
                    )}

                    <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-white/10">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSave}
                            disabled={loading}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded transition-colors disabled:opacity-50"
                        >
                            {loading ? 'Saving...' : 'Save Settings'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
