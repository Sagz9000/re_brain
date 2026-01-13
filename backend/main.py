from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import logging
import sys
import time
import os
import json
import uuid
import shutil
import subprocess
import requests
import threading
import re

ghidra_lock = threading.Lock()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
PROJECTS_DIR = "/data/projects"
JOBS_PENDING_DIR = "/data/jobs/pending"
BINARIES_DIR = "/data/binaries"

# Ensure directories exist
for d in [PROJECTS_DIR, JOBS_PENDING_DIR, BINARIES_DIR]:
    if not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

try:
    from search_engine import SearchEngine
except ImportError as e:
    logger.error(f"Failed to import SearchEngine: {e}")
    SearchEngine = None

app = FastAPI(title="reAIghidra API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


class ChatRequest(BaseModel):
    query: str
    model: str = "qwen2.5-coder:14b"
    history: Optional[List[dict]] = None
    current_file: Optional[str] = None
    current_function: Optional[str] = None
    current_address: Optional[str] = None

# Global SearchEngine instance
search_engine = None
try:
    if SearchEngine:
        search_engine = SearchEngine()
        logger.info("Search Engine initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize SearchEngine: {e}")

# Activity Log
activity_logs = []

def log_event(message, source="System"):
    timestamp = time.strftime("%H:%M:%S")
    event = {"time": timestamp, "message": message, "source": source}
    activity_logs.append(event)
    logger.info(f"[{source}] {message}")
    if len(activity_logs) > 100:
        activity_logs.pop(0)

@app.get("/")
def read_root():
    return {"status": "online", "service": "reAIghidra Backend"}

@app.get("/health")
def health_check():
    return {"status": "online"}

@app.get("/activity")
def get_activity():
    return activity_logs

@app.post("/ingest/binary")
def ingest_binary(data: dict):
    if not search_engine:
        return {"error": "Search engine not initialized"}
    
    funcs = data.get("functions", [])
    binary_name = data.get("binary", "unknown")
    collection = search_engine.client.get_or_create_collection("binary_functions")
    
    ids = []
    documents = []
    metadatas = []
    
    for f in funcs:
        f_id = f"{binary_name}_{f['address']}"
        ids.append(f_id)
        content = f"Function: {f['name']} at {f['address']}. Signature: {f['signature']}"
        if f.get('comment'):
            content += f". Comment: {f['comment']}"
        documents.append(content)
        metadatas.append({"source": "ghidra_analysis", "binary": binary_name, "type": "function"})
        
    summary_id = f"{binary_name}_summary"
    summary_content = f"Analysis Summary: The binary '{binary_name}' has been analyzed. It contains {len(ids)} functions exported from Ghidra."
    ids.append(summary_id)
    documents.append(summary_content)
    metadatas.append({"source": "ghidra_analysis", "binary": binary_name, "type": "summary"})
        
    if ids:
        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        log_event(f"Ingested {len(ids)} functions from {binary_name}", source="AI")
    
    return {"status": "success", "count": len(ids)}

def get_decompile(name: str, addr: str):
    return run_headless_script(name, "DecompileFunction.java", args=[addr], read_only=True)

@app.get("/binary/{name}/function/{addr}/decompile")
def get_decompile_endpoint(name: str, addr: str):
    return get_decompile(name, addr)

class EmulateRequest(BaseModel):
    address: str
    steps: int = 5
    stop_at: Optional[str] = None

@app.post("/binary/{name}/emulate")
def emulate_execution(name: str, req: EmulateRequest):
    args = [req.address, str(req.steps)]
    if req.stop_at:
        args.append(req.stop_at)
    return run_headless_script(name, "EmulateFunction.java", args=args, read_only=True)

class RenameRequest(BaseModel):
    target: str # Address or old name
    new_name: str

@app.post("/binary/{name}/rename")
def rename_function(name: str, req: RenameRequest):
    log_event(f"Renaming {req.target} to {req.new_name} in {name}", source="System")
    return run_headless_script(name, "RenameFunction.java", args=[req.target, req.new_name], read_only=False)

class CommentRequest(BaseModel):
    address: str
    comment: str
    type: str = "plate" # pre, post, eol, plate

@app.post("/binary/{name}/comment")
def set_comment(name: str, req: CommentRequest):
    log_event(f"Setting {req.type} comment at {req.address} in {name}", source="System")
    return run_headless_script(name, "SetComment.java", args=[req.address, req.comment, req.type], read_only=False)

def sanitize_json(obj):
    """Recursively convert NaN/Infinity to strings for valid JSON."""
    if isinstance(obj, float):
        import math
        if math.isnan(obj) or math.isinf(obj):
            return str(obj)
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_json(i) for i in obj]
    return obj

@app.post("/binary/{name}/batch_analysis")
def batch_analysis(name: str):
    log_event(f"Starting Batch Analysis for {name}", source="System")
    
    # 1. Run Ghidra Script to export all functions
    try:
        functions_data = run_headless_script(name, "BatchDecompile.java", args=[], read_only=True)
        if isinstance(functions_data, dict) and "error" in functions_data:
             return functions_data
        functions = functions_data if isinstance(functions_data, list) else [] # Expecting a list of functions
    except Exception as e:
        logger.error(f"Batch Decompile failed: {e}")
        return {"error": f"Batch Decompile failed: {str(e)}"}

    if not functions:
        return {"error": "No functions found or decompilation failed."}

    log_event(f"Extracted {len(functions)} functions. Starting AI Scan...", source="System")

    # 2. Iterate and AI Scan
    # We'll batch functions to avoid context limits. 5 functions per chunk?
    CHUNK_SIZE = 5
    findings = []
    
    # Limit total functions for now to avoid huge costs/time during testing (Timeout Prevention)
    functions = functions[:20] 

    for i in range(0, len(functions), CHUNK_SIZE):
        chunk = functions[i:i+CHUNK_SIZE]
        
        prompt = "Analyze the following functions for security interest. Look for:\n"
        prompt += "1. Encryption/Encoding logic (XOR, shifts, magic constants)\n"
        prompt += "2. Network activity (socket, connect, send, recv)\n"
        prompt += "3. Complex control flow (nested loops, state machines)\n"
        prompt += "\nReturn a JSON list of meaningful findings only. Format: [{'function': 'name', 'category': 'Encryption', 'details': '...'}]. If nothing interesting, return [].\n\n"
        
        for f in chunk:
            prompt += f"Function: {f['name']} @ {f['address']}\nCode:\n{f['code'][:1000]}\n\n" # Truncate code if too long
            
        try:
            # Call Ollama logic directly here (simplified from chat_endpoint)
            # Depending on how chat_endpoint is structured, proper way is to use requests to Ollama
            # For now, let's reuse a simple query function if available, or just call chat logic.
            # But chat logic expects history... let's just use requests to OLLAMA_HOST
            
            payload = {
                "model": "qwen2.5-coder:14b",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}
            }
            res = requests.post(f"{os.getenv('OLLAMA_HOST', 'http://localhost:11434')}/api/generate", json=payload)
            if res.status_code == 200:
                ai_text = res.json().get('response', '')
                # Parse JSON from AI
                try:
                    # Find JSON array in text
                    match = re.search(r'\[.*\]', ai_text, re.DOTALL)
                    if match:
                        chunk_findings = json.loads(match.group(0))
                        findings.extend(chunk_findings)
                except:
                    pass # AI didn't return valid JSON
        except Exception as e:
            logger.error(f"AI Chunk Scan failed: {e}")

    summary = f"Batch Analysis Complete. Scanned {len(functions)} functions. Found {len(findings)} items of interest."
    log_event(summary, source="AI")
    
    if search_engine:
        try:
             search_engine.store_finding(name, "deep_scan", summary, {"findings_count": len(findings)})
             # Store detailed findings as separate chunks if needed, but summary is good for now.
             if findings:
                  details = "\n".join([f"- {f.get('function')}: {f.get('details')}" for f in findings])
                  search_engine.store_finding(name, "deep_scan_findings", details, {"findings_count": len(findings)})
        except Exception as e:
             logger.error(f"Failed to store batch findings in RAG: {e}")

    return {"status": "success", "total_functions": len(functions), "findings": sanitize_json(findings)}

@app.post("/binary/{name}/memory_analysis")
def memory_analysis(name: str):
    log_event(f"Starting Memory Analysis for {name}", source="System")
    
    # 1. Run Ghidra Script
    try:
        mem_data = run_headless_script(name, "MemoryMapExport.java", args=[], read_only=True)
        if isinstance(mem_data, dict) and "error" in mem_data:
             return mem_data
        if not isinstance(mem_data, dict):
             return {"error": "Invalid memory analysis data format."}
             
    except Exception as e:
        logger.error(f"Memory Export failed: {e}")
        return {"error": f"Memory Export failed: {str(e)}"}

    # 2. AI Processing
    prompt = "Analyze the following memory layout and pointers for a binary. \n"
    prompt += "Identify security risks (e.g. RWX sections, suspicious segments).\n"
    prompt += "Explain the layout (Stack, Heap, Code, Data).\n"
    prompt += "Infer the purpose of the pointers provided.\n\n"
    
    blocks = mem_data.get('blocks', [])
    pointers = mem_data.get('pointers', [])
    
    prompt += "Memory Blocks:\n" + json.dumps(blocks, indent=2) + "\n\n"
    prompt += "Sample Pointers:\n" + json.dumps(pointers[:50], indent=2) + "\n\n" # Limit to top 50
    
    prompt += "Return a concise analysis summary."

    try:
        payload = {
            "model": "qwen2.5-coder:14b",
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2}
        }
        res = requests.post(f"{os.getenv('OLLAMA_HOST', 'http://localhost:11434')}/api/generate", json=payload)
        ai_response = "AI Analysis Failed."
        if res.status_code == 200:
             ai_response = res.json().get('response', 'No response.')
             
        log_event("Memory Analysis Completed.", source="AI")
        
        if search_engine:
             search_engine.store_finding(name, "memory_scan", ai_response, {"blocks_count": len(blocks)})

        return {"status": "success", "analysis": ai_response, "data": mem_data}
        
    except Exception as e:
        return {"error": f"AI Scan failed: {e}"}


    except Exception as e:
        return {"error": f"AI Scan failed: {e}"}

@app.post("/binary/{name}/cipher_analysis")
def cipher_analysis(name: str):
    log_event(f"Starting Cipher Analysis for {name}", source="System")
    
    # 1. Run Ghidra Script
    try:
        cipher_funcs = run_headless_script(name, "CipherScan.java", args=[], read_only=True)
        if isinstance(cipher_funcs, dict) and "error" in cipher_funcs:
             return cipher_funcs
        if not isinstance(cipher_funcs, list):
             cipher_funcs = []
             
    except Exception as e:
        logger.error(f"Cipher Scan failed: {e}")
        return {"error": f"Cipher Scan failed: {str(e)}"}

    if not cipher_funcs:
        return {"status": "success", "analysis": "No suspicious bitwise/cipher logic found.", "findings": []}

    # 2. AI Processing
    prompt = "Analyze the following functions for encryption, encoding, or hashing logic.\n"
    prompt += "Identify the likely algorithm (e.g. RC4, AES, XOR Stream, Base64, CRC32, etc.).\n"
    prompt += "Provide specific instructions on how to decode the data (e.g. 'XOR with key 0x55', 'Shift right by 2').\n"
    prompt += "If it looks like a standard library function (e.g. memcpy optimized), ignore it.\n\n"
    
    try:
        for f in cipher_funcs:
            # Safer access with defaults
            name = f.get('name', 'unknown')
            addr = f.get('address', 'unknown')
            score = f.get('score', 0)
            code = f.get('code', '')
            prompt += f"Function: {name} @ {addr} (Bitwise Ops: {score})\n"
            prompt += f"Code:\n{code[:2000]}\n\n" # Truncate to save context
    except Exception as e:
        logger.error(f"Cipher Prompt Gen Failed: {e}")
        return {"error": f"Cipher Prompt Gen Failed: {e}"}
    
    prompt += "Return a concise report with findings and decoding suggestions."

    try:
        payload = {
            "model": "qwen2.5-coder:14b",
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1}
        }
        res = requests.post(f"{os.getenv('OLLAMA_HOST', 'http://localhost:11434')}/api/generate", json=payload)
        ai_response = "AI Analysis Failed."
        if res.status_code == 200:
             ai_response = res.json().get('response', 'No response.')
             
        log_event("Cipher Analysis Completed.", source="AI")
        
        if search_engine:
             search_engine.store_finding(name, "cipher_scan", ai_response, {"suspicious_functions": len(cipher_funcs)})

        return {"status": "success", "analysis": ai_response, "findings": cipher_funcs}
        
    except Exception as e:
        return {"error": f"AI Scan failed: {e}"}

class DataTypeRequest(BaseModel):
    type_name: str
    category_path: Optional[str] = None

@app.post("/binary/{name}/datatype/preview")
def get_datatype_preview(name: str, req: DataTypeRequest):
    file_path = os.path.join(BINARIES_DIR, name)
    if not os.path.exists(file_path):
        return JSONResponse(status_code=404, content={"error": "File not found"})
    
    # Clean path argument
    path_arg = req.category_path if req.category_path else ""

    logger.info(f"Generating preview for type '{req.type_name}' in {name}")
    
    result = run_headless_script(
        name, 
        "GetDataTypePreview.java", 
        args=[req.type_name, path_arg],
        read_only=True
    )
    
    if "error" in result:
        return JSONResponse(status_code=500, content=result)
        
    return sanitize_json(result)

@app.post("/binary/{name}/malware_analysis")
def malware_analysis(name: str):
    log_event(f"Starting Malware Analysis for {name}", source="System")
    
    # 1. Run Ghidra Script
    try:
        malware_data = run_headless_script(name, "MalwareScan.java", args=[], read_only=True)
        if "error" in malware_data:
             return malware_data
        if not isinstance(malware_data, dict):
             malware_data = {"imports": [], "strings": []}
             
    except Exception as e:
        logger.error(f"Malware Scan failed: {e}")
        return {"error": f"Malware Scan failed: {str(e)}"}

    if not malware_data['imports'] and not malware_data['strings']:
        return {"status": "success", "analysis": "No obvious malware indicators found.", "findings": malware_data}

    # 2. AI Processing
    prompt = "Analyze the following binary artifacts for malware, C2 (Cobalt Strike, Metasploit, etc.), or shellcode behavior.\n"
    prompt += "Look for 'Injection' capabilities (VirtualAlloc, CreateRemoteThread), 'Network' Beacons (WinINet, User-Agents), and 'Evasion' (Anti-Debug).\n"
    prompt += "Assess the threat level (Clean, Suspicious, Malicious) and explain why.\n\n"
    
    prompt += "Suspicious Imports:\n" + json.dumps(malware_data['imports'], indent=2) + "\n\n"
    prompt += "Suspicious Strings:\n" + json.dumps(malware_data['strings'][:50], indent=2) + "\n\n" # Limit
    
    prompt += "Return a concise threat assessment."

    try:
        payload = {
            "model": "qwen2.5-coder:14b",
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1}
        }
        res = requests.post(f"{os.getenv('OLLAMA_HOST', 'http://localhost:11434')}/api/generate", json=payload)
        ai_response = "AI Analysis Failed."
        if res.status_code == 200:
             ai_response = res.json().get('response', 'No response.')
             
        log_event("Malware Analysis Completed.", source="AI")
        
        if search_engine:
             search_engine.store_finding(name, "malware_scan", ai_response, {"risk_imports": len(malware_data.get('imports', [])), "risk_strings": len(malware_data.get('strings', []))})

        return {"status": "success", "analysis": ai_response, "findings": malware_data}
        
    except Exception as e:
        return {"error": f"AI Scan failed: {e}"}

@app.post("/chat")
def chat_endpoint(request: ChatRequest):
    if not search_engine:
        return {"response": "Search engine not initialized. Check logs."}
    
    log_event(f"User Query: {request.query}", source="User")

    context_str = ""
    context_hits = []
    
    # Files Context
    file_list = []
    if os.path.exists(BINARIES_DIR):
        file_list = [f for f in os.listdir(BINARIES_DIR) if os.path.isfile(os.path.join(BINARIES_DIR, f))]
    file_count = len(file_list)
    file_list_str = ", ".join(file_list) if file_list else "None"
    
    current_file = request.current_file or "None"
    current_address = request.current_address or "None"
    current_function = request.current_function or "None"
    
    arch_info = "Unknown (Analysis Pending)"
    decompiled_code = "No code selected."

    # Fetch Architecture & Decompiled Code if applicable
    if request.current_file:
         # Arch
         arch_path = f"{BINARIES_DIR}/{request.current_file}.arch.txt"
         if os.path.exists(arch_path):
             with open(arch_path, 'r') as f: arch_info = f.read().strip()
         
         # Decompiled Code
         if request.current_address:
             try:
                 # Re-use run_headless_script logic for decompilation on the fly
                 # Note: Ideally cache this, but for now we run it on demand (can be slow ~3-5s)
                 # Optimized: use 'DecompileAt.java' (need to make sure this exists or inline it)
                 # Actually, let's use the existing endpoint logic
                 result = get_decompile(request.current_file, request.current_address)
                 if isinstance(result, dict) and "code" in result:
                     decompiled_code = result["code"]
                 elif isinstance(result, dict) and "error" in result:
                     decompiled_code = f"Decompilation failed: {result['error']}"
             except Exception as e:
                 decompiled_code = f"Decompilation error: {str(e)}"

    # RAG Context (ChromaDB)
    try:
        if search_engine and search_engine.client:
            # New centralized search with binary scoping
            rrf_results = search_engine.search(request.query, top_k=5, binary_context=current_file)
            
            context_str += search_engine.format_context(rrf_results)
            
            # Track hits for UI
            context_hits = [r['meta'].get('function', r['meta'].get('type', 'doc')) for r in rrf_results]

    except Exception as e:
        logger.error(f"RAG Error: {e}")
        context_str = f"RAG unavailable: {e}"

    # Format History
    history_str = ""
    if request.history:
        for msg in request.history[-5:]:
            role = msg.get('role', 'user').upper()
            content = msg.get('content', '')
            history_str += f"{role}: {content}\n"

    system_prompt = """You are the Lead Malware Researcher (re-Brain). You analyze binaries for malicious intent.
Rules:
1. Technical Precision: Use terms like "prologue," "indirect call," "stack canary," etc.
2. Hypothesis Generation: Identify functions/behaviors based on imports/logic.
3. Interactive Addresses: Format addresses as `[0x...]` (e.g. `[0x401000]`).
4. Interactive Functions: Format functions as `[func:Name@0xAddr]`.
5. Reasoning: ALWAYS wrap your internal logic/planning in `<think>` and `</think>` tags.
6. UI Control: Use standalone JSON blocks for actions.
   - Rename: `{ "action": "rename", "target": "FUN_...", "new_name": "login_check" }`
   - Comment: `{ "action": "comment", "address": "0x401000", "comment": "...", "type": "plate" }`
   - Goto: `{ "action": "goto", "address": "0x401000" }`
   - Emulate: `{ "action": "emulate", "address": "0x401000", "steps": 5, "stop_at": "0x401050" }`

   INTERACTIVE DEBUGGING:
   - When you use `emulate`, the SYSTEM will output the Result Trace in the next message.
   - You MUST CHECK REGISTERS in the result (e.g. "RAX=0x1").
   - If a Breakpoint is reached, decide the next step.

NEGATIVE CONSTRAINTS:
- DO NOT output conversational filler (e.g., "I will now analyze", "I decide to").
- DO NOT repeat the prompt instructions or the schema labels in your response.
- DO NOT explain your reasoning outside of <think> tags.
- DO NOT use bullet points for JSON commands. Use ```json blocks.
"""

    context_prompt = f"""Environment:
- Focus: {current_file} @ {current_address} ({current_function})
- Architecture: {arch_info}

CURRENT CODE:
```c
{decompiled_code}
```

RAG Context:
{context_str}

History:
{history_str}

User Query: {request.query}

Respond using the schema:
<think> (Your internal reasoning) </think>
## Analysis
(Technical breakdown with interactive links)
## Actions
(Optional: ```json block with UI commands)
"""

    try:
        ollama_base = os.getenv("OLLAMA_HOST", "http://re-ai:11434")
        ollama_res = requests.post(
            f"{ollama_base}/api/generate",
            json={
                "model": request.model,
                "system": system_prompt,
                "prompt": context_prompt,
                "stream": False,
                "options": {
                    "num_ctx": 8192,
                    "temperature": 0.2 # Lower temperature for structural stability
                }
            },
            timeout=120 # Give it 2 minutes for deep analysis, but the frontend will likely abort at 90
        )
        response_text = ollama_res.json().get('response', "I couldn't generate a response.")
        
        # Extract thinking process for console output
        think_match = re.search(r'<think>([\s\S]*?)</think>', response_text, re.IGNORECASE)
        if think_match:
            thought = think_match.group(1).strip()
            if thought:
                log_event(f"Reasoning: {thought}", source="AI")

        log_event(f"AI Replied using {len(context_hits)} context blocks", source="AI")
        return {
            "response": response_text,
            "context_used": context_hits
        }
    except Exception as e:
        logger.error(f"LLM Call Failed: {e}")
        return {"response": f"AI error: {e}"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    is_new_project: bool = Form(...)
):
    try:
        os.makedirs(BINARIES_DIR, exist_ok=True)
        file_location = f"{BINARIES_DIR}/{file.filename}"
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
            
        job_id = str(uuid.uuid4())
        job_data = {
            "id": job_id,
            "file_path": f"/ghidra/binaries/{file.filename}", 
            "project_name": project_name,
            "is_new": is_new_project
        }
        
        job_path = f"{JOBS_PENDING_DIR}/{job_id}.json"
        with open(job_path, "w") as f:
            json.dump(job_data, f)
            
        log_event(f"File uploaded and queued: {file.filename}", source="System")
        return {"status": "queued", "job_id": job_id, "file": file.filename}
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        return {"error": str(e)}

@app.get("/binaries")
def list_binaries():
    if not os.path.exists(BINARIES_DIR):
        return []
    return [f for f in os.listdir(BINARIES_DIR) if os.path.isfile(os.path.join(BINARIES_DIR, f))]

@app.delete("/binary/{name}")
def delete_binary(name: str):
    file_path = os.path.join(BINARIES_DIR, name)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            log_event(f"Deleted file: {name}", source="System")
            
            # Clean up RAG knowledge
            if search_engine:
                 search_engine.delete_project_knowledge(name)
                 log_event(f"Deleted RAG Knowledge for: {name}", source="System")

            return {"status": "deleted", "file": name}
        else:
            return {"error": "File not found"}
    except Exception as e:
        logger.error(f"Delete failed: {e}")
        return {"error": str(e)}

@app.get("/binary/{name}/hex")
def get_hex_view(name: str, offset: int = 0, limit: int = 512):
    file_path = os.path.join(BINARIES_DIR, name)
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    try:
        with open(file_path, "rb") as f:
            file_size = os.path.getsize(file_path)
            f.seek(offset)
            data = f.read(limit)
            return {
                "hex": data.hex(),
                "offset": offset,
                "limit": limit,
                "total_size": file_size
            }
    except Exception as e:
        return {"error": str(e)}

@app.get("/binary/{name}/functions")
def get_functions(name: str):
    if not search_engine:
        return {"error": "Search engine not initialized"}
        
    try:
        collection = search_engine.client.get_collection("binary_functions")
        res = collection.get(where={"binary": name})
        
        funcs = []
        if res['ids']:
            for i, doc in enumerate(res['documents']):
                meta = res['metadatas'][i]
                if meta.get('type') == 'function':
                   try:
                       content = doc
                       name_part = content.split("Function: ")[1].split(" at ")[0]
                       addr_part = content.split(" at ")[1].split(". Signature: ")[0]
                       sig_part = content.split("Signature: ")[1]
                       funcs.append({
                           "name": name_part,
                           "address": addr_part,
                           "signature": sig_part
                       })
                   except:
                       continue
        return funcs
    except Exception as e:
        logger.error(f"Error fetching functions: {e}")
        return []

@app.get("/binary/{name}/strings")
def get_strings(name: str):
    file_path = os.path.join(BINARIES_DIR, name)
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    try:
        # -t x outputs offset in hex
        result = subprocess.run(['strings', '-n', '6', '-t', 'x', file_path], capture_output=True, text=True)
        
        output_data = []
        # Output format is "  offset string"
        # We need to parse this
        lines = result.stdout.splitlines()
        for line in lines:
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                output_data.append({
                    "offset": f"0x{parts[0]}", 
                    "value": parts[1]
                })
                
        return output_data[:2000] # Increased limit slightly, frontend can handle it
    except Exception as e:
        return {"error": str(e)}

@app.get("/projects")
def list_projects():
    try:
        if not os.path.exists(PROJECTS_DIR):
            return []
        projects = [f for f in os.listdir(PROJECTS_DIR) if os.path.isdir(os.path.join(PROJECTS_DIR, f))]
        return projects
    except Exception as e:
        logger.error(f"List projects failed: {e}")
        return []

@app.delete("/projects/{name}")
def delete_project(name: str):
    """Delete a Ghidra project and all associated files"""
    try:
        import shutil
        
        # Security: prevent path traversal
        if ".." in name or "/" in name or "\\" in name:
            return {"error": "Invalid project name"}
        
        # Normalize name: strip extension if provided from UI listing
        base_name = name
        if base_name.endswith(".rep"):
            base_name = base_name[:-4]
        elif base_name.endswith(".gpr"):
            base_name = base_name[:-4]

        project_dir = PROJECTS_DIR
        if not os.path.exists(project_dir):
            return {"error": "Projects directory not found"}
        
        # Delete .gpr file and .rep directory
        gpr_file = os.path.join(project_dir, f"{base_name}.gpr")
        rep_dir = os.path.join(project_dir, f"{base_name}.rep")
        
        deleted = []
        if os.path.exists(gpr_file):
            os.remove(gpr_file)
            deleted.append(f"{base_name}.gpr")
        
        if os.path.exists(rep_dir):
            shutil.rmtree(rep_dir)
            deleted.append(f"{base_name}.rep")
        
        if not deleted:
            # Fallback: maybe the user really meant a directory named exactly "name" that isn't a standard ghidra project structure?
            # But mostly we care about cleaning up the project artifacts.
            # If we didn't find the calculated ones, try deleting exactly what was passed if it exists
            exact_path = os.path.join(project_dir, name)
            if os.path.exists(exact_path):
                 if os.path.isdir(exact_path):
                     shutil.rmtree(exact_path)
                 else:
                     os.remove(exact_path)
                 deleted.append(name)
                 return {"status": "success", "deleted": deleted, "project": name}

            return {"error": f"Project '{base_name}' not found (checked .gpr and .rep)"}
        
        log_event(f"Deleted project: {name}", source="System")
        return {"status": "success", "deleted": deleted, "project": name}
        
    except Exception as e:
        logger.error(f"Delete project failed: {e}")
        return {"error": str(e)}

@app.get("/binary/{name}/tree")
def get_program_tree(name: str):
    return run_headless_script(name, "GetMemoryBlocks.java", read_only=True)


@app.get("/binary/{name}/symbols")
def get_symbols(name: str):
    return run_headless_script(name, "GetSymbols.java", read_only=True)

def extract_json_from_ghidra_output(output: str) -> Optional[dict]:
    """Robustly extracts JSON from Ghidra's stdout log stream."""
    json_str = ""
    capture = False
    
    # Heuristic: collect lines between markers
    for line in output.splitlines():
        if "JSON_START" in line or ">START" in line:
            capture = True
            continue
        if "JSON_END" in line or ">END" in line:
            capture = False
            break
        if capture:
            # Robustly strip Ghidra log noise (e.g. "INFO  GetSymbols.java> {")
            # We only strip if the line STARTS with a level and has a script marker
            import re
            # 1. Strip script prefixes "INFO ScriptName> "
            clean_line = re.sub(r'^\s*(?:INFO|WARN|ERROR).*?>\s*', '', line).strip()
            
            # 2. Filter out raw system logs that interrupted the JSON stream
            # e.g. "INFO  Class search complete..."
            # Valid JSON lines (pretty printed) start with {, }, [, ], ", or are blank/numeric.
            # They should NOT start with "INFO" unless it's a key, which would be quoted.
            if clean_line.startswith(("INFO ", "WARN ", "ERROR ", "REPORT ", "DEBUG ")):
                continue
                
            json_str += clean_line + "\n"
    
    if not json_str.strip():
        # Fallback: find any line that looks like a standalone JSON object
        for line in output.splitlines():
            clean_line = line.strip()
            if clean_line.startswith("{") or clean_line.startswith("["):
                try:
                    import json
                    return json.loads(clean_line)
                except:
                    continue
        return None

    # Final cleanup: find the actual JSON bounds to ignore any remaining trailing/leading noise
    try:
        import json
        # Try direct load first
        return json.loads(json_str) 
    except json.JSONDecodeError:
        # If nested markers or partial logs, try to find the first { or [
        start_idx = -1
        if "{" in json_str: start_idx = json_str.find("{")
        if "[" in json_str and (start_idx == -1 or json_str.find("[") < start_idx):
            start_idx = json_str.find("[")
            
        if start_idx != -1:
            try:
                candidate = json_str[start_idx:]
                # Rough balancing check or just try to load
                return json.loads(candidate)
            except:
                pass
                
    return None

def run_headless_script(name: str, script: str, timeout: int = 120, args: list = None, read_only: bool = True):
    project_dir = "/data/projects"
    project_name = None
    
    if os.path.exists(project_dir):
        # Gather all candidates first
        candidates = [f.replace(".gpr", "") for f in os.listdir(project_dir) if f.endswith(".gpr")]
        
        if candidates:
            # 1. Exact match (ignoring case)
            name_stem = os.path.splitext(name)[0].lower()
            for cand in candidates:
                if cand.lower() == name_stem:
                    project_name = cand
                    break
            
            # 2. Prefix match (e.g. vlc-3.0.21.exe matches project 'vlc')
            if not project_name:
                for cand in candidates:
                    if name.lower().startswith(cand.lower()):
                        project_name = cand
                        break
                        
            # 3. Fallback: Check if 'flare' exists (common CTF bucket)
            if not project_name and "flare" in candidates:
                project_name = "flare"
                
            # 4. Last resort: substring match in either direction
            if not project_name:
                for cand in candidates:
                    if cand.lower() in name.lower() or name.lower() in cand.lower():
                        project_name = cand
                        break

            # 5. Absolute fallback: Pick the first one
            if not project_name:
                project_name = candidates[0]
            
    if not project_name:
        return {"error": "No Ghidra project found"}

    # Create a temp file path for JSON output
    # We use /data/jobs because it is a shared volume between backend and ghidra containers
    import uuid
    import json # Added import for json
    job_id = str(uuid.uuid4())
    output_filename = f"{job_id}.json"
    # re-api2 does not have /ghidra/jobs mounted, so we must use /data/jobs (which is mounted)
    output_path_container = f"/data/jobs/{output_filename}" 
    output_path_backend = f"/data/jobs/{output_filename}" # Path inside Backend container
    
    # Ensure directory exists
    os.makedirs("/data/jobs", exist_ok=True)

    cmd_process = [
        "/ghidra/support/analyzeHeadless",
        project_dir,
        project_name,
        "-process", name,
        "-noanalysis",
        "-scriptPath", "/ghidra_scripts"
    ]

    if read_only:
        cmd_process.append("-readOnly")
        
    cmd_process.extend(["-postScript", script, output_path_container])
    
    # Append any user arguments AFTER the output path
    if args:
        cmd_process.extend(args)
    
    
    try:
        log_event(f"Attempting script {script} on {name} (Project: {project_name}) [Out: {output_filename}]", source="Ghidra")
        
        with ghidra_lock:
            # 1. Primary Attempt: Run script
            result = subprocess.run(cmd_process, capture_output=True, text=True, timeout=timeout)
            output = result.stdout
            stderr = result.stderr
            
            # Log the raw output for debugging
            logger.info(f"GHIDRA STDOUT: {output}")
            logger.info(f"GHIDRA STDERR: {stderr}")

            # Check if output file exists with retries (fs sync latency)
            import time
            found = False
            for i in range(50): # Try for 5 seconds (50 * 0.1s)
                if os.path.exists(output_path_backend):
                    found = True
                    break
                time.sleep(0.1)

            if found:
                try:
                    with open(output_path_backend, 'r') as f:
                        file_content = f.read()
                        if not file_content.strip():
                             return {"error": "Output file exists but is empty"}
                        json_data = json.loads(file_content)
                    
                    # Cleanup
                    os.remove(output_path_backend)
                    return json_data
                except json.JSONDecodeError as e:
                     logger.error(f"JSON Parse Error: {e}")
                     return {
                         "error": f"JSON Parse Error: {str(e)}", 
                         "file_content_preview": file_content[:500] if 'file_content' in locals() else "N/A"
                     }
                except Exception as e:
                    logger.error(f"Failed to read output file: {e}")
                    return {"error": f"Read Error: {str(e)}"}

            # Debugging File Not Found
            else:
                logger.error(f"Output file not found at {output_path_backend} after 5s wait")
                listing = "Listing failed"
                try:
                    listing = str(os.listdir(os.path.dirname(output_path_backend)))
                except: pass
                
                return {
                    "error": "Output file not found after wait",
                    "directory_listing": listing,
                    "target_path": output_path_backend,
                    "ghidra_stdout": output
                }

            # If we are here, we essentially failed or returned above.
            # The auto-import fallback is below, but we should probably just return the failure if the primary script failed this hard.
            # However, logic dictates we attempt fallback ONLY if the script failed due to "not found" (which implies input binary missing).
            
            # ... existing fallback logic ...
            # Actually, since we are returning detailed errors above, we might skip fallback if it was a file-not-found-AFTER-execution issue?
            # No, proceed to fallback logic only if output suggests it.
            
            # BUT: strict "else" block above returns. "if found" returns.
            # So code below is unreachable for the primary attempt?
            # Yes. This logic refactoring replaces the fall-through.
            
            # Wait, we need to handle the case where Ghidra explicitly says "file not found" (input binary) 
            # effectively BEFORE checking for output file? 
            # Or if output file is missing, we check output for "not found".
            
            pass 
            # Refactoring to remove unreachable code warning and keep fallback logic accessible
            
            # ... (let's keep the fallback accessible if file not found) ...


            # 2. Fallback: If no JSON, check if we need to auto-import
            if "ERROR: Unable to prompt user" in output or "not found" in output.lower():
                log_event(f"File {name} not in project, attempting auto-import...", source="Ghidra")
                file_path = os.path.join(BINARIES_DIR, name)
                if os.path.exists(file_path):
                    # Try to import + run script in one go
                    # We use -noanalysis for speed if we just want the script output
                    cmd_import = [
                        "/ghidra/support/analyzeHeadless",
                        project_dir,
                        project_name,
                        "-import", file_path,
                        "-overwrite",
                        "-noanalysis",
                        "-scriptPath", "/ghidra_scripts",
                        "-postScript", script,
                        output_path_container
                    ]
                    if args:
                        cmd_import.extend(args)

                    result_imp = subprocess.run(cmd_import, capture_output=True, text=True, timeout=timeout)
                    output = result_imp.stdout
                    stderr = result_imp.stderr 
                    
                    if os.path.exists(output_path_backend):
                        try:
                            with open(output_path_backend, 'r') as f:
                                json_data = json.load(f)
                            os.remove(output_path_backend)
                            return json_data
                        except Exception as e:
                            logger.error(f"Failed to read/parse output file {output_path_backend}: {e}")
                else:
                    log_event(f"Binary {name} not found on disk at {file_path}", source="Ghidra")

            # 3. Final failure reporting (inside lock to ensure we capture the right state)
            logger.error(f"Ghidra failure for {name}: {output}\nSTDERR: {stderr}")
            if os.path.exists(output_path_backend):
                 os.remove(output_path_backend) # Cleanup even on failure
                 
            return {
                "error": "Script produced no output file (Wait Mode 5s)",
                "stdout": output,
                "stderr": stderr,
                "project": project_name,
                "script": script,
                "cmd": " ".join(cmd_process)
            }

    except subprocess.TimeoutExpired:

        log_event(f"Timeout running {script} on {name}", source="Ghidra")
        if os.path.exists(output_path_backend):
             os.remove(output_path_backend)
        return {"error": f"Script {script} timed out ({timeout}s)"}
    except Exception as e:
        log_event(f"General error in run_headless_script: {str(e)}", source="Ghidra")
        if os.path.exists(output_path_backend):
             os.remove(output_path_backend)
        return {"error": str(e)}


@app.get("/binary/{name}/memory")
def get_memory_blocks(name: str):
    return run_headless_script(name, "GetMemoryBlocks.java", read_only=True)

@app.get("/binary/{name}/calltree")
def get_calltree(name: str):
    return run_headless_script(name, "GetCallTree.java", read_only=True)

@app.get("/binary/{name}/datatypes")
def get_datatypes(name: str):
    return run_headless_script(name, "GetDataTypes.java", timeout=120, read_only=True)

@app.get("/binary/{name}/bookmarks")
def get_bookmarks(name: str):
    return run_headless_script(name, "GetBookmarks.java", read_only=True)

@app.get("/binary/{name}/function/{addr}/cfg")
def get_function_cfg(name: str, addr: str):
    return run_headless_script(name, "GetFunctionCFG.java", args=[addr], read_only=True)

class RunRequest(BaseModel):
    code: str

@app.post("/run")
def run_python(req: RunRequest):
    try:
        # Run code in a subprocess for isolation (to some extent)
        # Using sys.executable ensures we use the same python env (with installed deps)
        result = subprocess.run(
            [sys.executable, "-c", req.code],
            capture_output=True,
            text=True,
            timeout=30 # 30s timeout for safety
        )
        return {
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "Execution timed out (30s limit)", "output": "", "exit_code": -1}
    except Exception as e:
        return {"error": str(e), "output": "", "exit_code": -1}

@app.get("/binary/{name}/function/{addr}/cfg")
def get_function_cfg(name: str, addr: str):
    return run_headless_script(name, "GetFunctionCFG.java", args=[addr], read_only=True)



class RenameRequest(BaseModel):
    function: str
    new_name: str
    address: Optional[str] = None

@app.post("/binary/{name}/rename")
def rename_function(name: str, req: RenameRequest):
    # Depending on whether address is provided or not, we choose the target argument
    # If address is available, it's safer to use it to resolve ambiguity
    target = req.address if req.address else req.function
    return run_headless_script(name, "RenameFunction.java", args=[target, req.new_name], read_only=False)


class CommentRequest(BaseModel):
    address: str
    comment: str
    type: str = "plate" # "plate", "pre", "post", "eol"

@app.post("/binary/{name}/comment")
def set_comment(name: str, req: CommentRequest):
    return run_headless_script(name, "SetComment.java", args=[req.address, req.comment, req.type], read_only=False)

@app.get("/binary/{name}/xrefs")
def get_xrefs(name: str, address: str):
    return run_headless_script(name, "GetXRefs.java", args=[address], read_only=True)
