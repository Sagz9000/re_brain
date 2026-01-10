# re-Brain

**AI-Powered Reverse Engineering Environment**

reAIghidra is a containerized, multi-modal RAG system that integrates Ghidra with specialized AI knowledge streams to assist in binary analysis and malware reverse engineering.

![re-Brain AI Analysis](pictures/ui_ai.png)

---

## 🏛️ Architecture

The re-Brain ecosystem is composed of 5 specialized Docker containers working in concert:

```mermaid
graph TD
    User([User / Browser])
    
    subgraph "Docker Environment (re-net)"
        Web[re-web: Next.js Frontend]
        API[re-api: FastAPI Backend]
        Ghidra[re-ghidra: Analysis Engine]
        Memory[(re-memory: ChromaDB)]
        AI[re-ai / Host Ollama: LLM]
    end

    subgraph "Knowledge Base"
        Docs[Ghidra Docs]
        Mal[Malware Tactics]
        Pat[Compiler Patterns]
        Exp[Expert Writeups]
    end

    User <-->|HTTP: 3000| Web
    Web <-->|VNC: 6080| Ghidra
    Web <-->|API: 8005| API
    
    API <-->|RAG Search| Memory
    API <-->|Inference| AI
    
    Ghidra -->|Decompiled Funcs| API
    Docs & Mal & Pat & Exp -->|Ingestion| API
```

### Core Components
1.  **re-web**: Modern Next.js interface providing terminal-like flexibility with floating windows and VNC integration for Ghidra access.
2.  **re-api**: FastAPI-driven "Brain" that manages RAG (Retrieval-Augmented Generation), search ranking (RRF), and orchestration.
3.  **re-ghidra**: Headless and VNC-enabled Ghidra instance for deep binary analysis and script execution.
4.  **re-ai**: Local Ollama instance (GPU-accelerated) providing high-performance LLM inference without external API dependencies.
5.  **re-memory**: ChromaDB vector store containing ingested documentation, malware tactics, and decompiler snippets.

---

## 🚀 Feature Walkthrough & AI Analysis

### UI Customization & Workspace Layout
The interface is designed for analyst productivity, allowing for a fully custom workspace. Floating windows can be opened, closed, and rearranged.

- **Bytes & Strings**: The **Bytes** (Hex) and **Defined Strings** windows can be docked or moved to clear center-stage for code analysis.
- **Optimized Chat**: The **re-Brain-AI** panel can be resized (e.g., to 50% width) to facilitate simultaneous code review and AI consultation.

![UI Layout](pictures/ui_layout.png)

### In-Depth AI Binary Analysis
Perform deep-dive triage on target binaries using the persistent AI Analyst.

#### Case Study: `hwmonitor_1.53.exe`
1.  **Selection**: Select the target binary from the File Explorer.
2.  **Prompting**: Issue descriptive analysis requests in natural language.
    - *Query:* `"Geve a full step by step break down and analysis of hwmonitor_1.53.exe"`
3.  **RAG Triage**: The system performs a multi-stream search across its internal knowledge base to identify patterns, Ghidra API usage, and known malware tactics.

![AI Analysis](pictures/ai_analysis.png)

---

## 🔧 Missing or Non-Working Features

While the core orchestration is functional, several features are currently under development or require manual configuration:

1.  **AI Response Persistency**: Currently, the AI bot may occasionally return *"I couldn't generate a response"* if the backend inference engine (Ollama) times out or if the RAG context retrieval returns zero relevant blocks for a specific binary version.
2.  **Automated Ingestion (Scripts)**: While `AnalyzeAndIngest.py` exists, its integration with the frontend's "Analyze" button is currently manual in several build environments.
3.  **Window State Persistence**: Layout arrangements (like 50% chat width) do not persist across page refreshes.
4.  **Model Specificity**: The system is optimized for `qwen2.5:7b`, but automated model-pulling during initial container setup may require manual intervention (`ollama pull`) in some Docker configurations.

---

## ⚡ Quick Start

### Prerequisites
- Docker & Docker Compose
- NVIDIA GPU (Recommended)

### Implementation
```bash
# 1. Fresh build (Clear previous data)
docker-compose down -v

# 2. Launch Stack
docker-compose up --build -d
```
Access the environment at `http://localhost:3000`.
