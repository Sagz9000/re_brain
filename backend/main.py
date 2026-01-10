from fastapi import FastAPI, File, UploadFile, Form
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
    allow_origins=["*"], # Allow all origins for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    query: str
    model: str = "qwen3-vl:8b"
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

@app.post("/chat")
def chat_endpoint(request: ChatRequest):
    if not search_engine:
        return {"error": "Search engine not initialized. Check logs."}
    
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
                 result = decompile_function(request.current_file, request.current_address)
                 if isinstance(result, dict) and "code" in result:
                     decompiled_code = result["code"]
                 elif isinstance(result, dict) and "error" in result:
                     decompiled_code = f"Decompilation failed: {result['error']}"
             except Exception as e:
                 decompiled_code = f"Decompilation error: {str(e)}"

    # RAG Context (ChromaDB)
    try:
        if request.current_file and search_engine and search_engine.client:
            coll = search_engine.client.get_or_create_collection(name=f"ghidra_{request.current_file}")
            # Query related to user input
            results = coll.query(
                query_texts=[request.query],
                n_results=3
            )
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    meta = results['metadatas'][0][i]
                    func_name = meta.get('function', 'unknown')
                    context_hits.append(func_name)
                    context_str += f"\n--- Function: {func_name} ---\n{doc}\n"
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

    final_prompt = f"""System Role: You are the Lead Malware Researcher (re-Brain). You are assisting a user in reversing a binary. You think in terms of execution flow, memory corruption, and adversarial intent. You are concise, technical, and never explain basic concepts unless asked.

Environment State:
- Analyzed Files: {file_count} ([{file_list_str}])
- Current Focus: {current_file} at address {current_address}
- Current Function: {current_function}
- Architecture: {arch_info}

CURRENT CODE (Decompiled):
```c
{decompiled_code}
```

RAG & Analysis Context:
{context_str}

Chat History:
{history_str}

Task Rules:
1. Technical Precision: Use terms like "prologue," "indirect call," "stack canary," and "PIC code" where appropriate.
2. Hypothesis Generation: If you see an unknown function, suggest what it might be based on its imports.
3. Interactive Addresses: When mentioning an address or function start, ALWAYS format it as `[0x...]` (e.g., `[0x401000]`). This allows the user to click it.
4. UI Control: To forcefully change the view, use the UI_COMMAND block.
5. If the user asks about the code, refer to the "CURRENT CODE" block above.

Output Schema:
- Detailed Analysis: Bulleted insights into the code/logic. Use `[0x...]` for all addresses.
- Command Block: A standalone JSON block labeled UI_COMMAND: (if applicable)

User Query: {request.query}

Respond now:"""

    try:
        ollama_res = requests.post(
            "http://re-ai:11434/api/generate",
            json={
                "model": request.model,
                "prompt": final_prompt,
                "stream": False,
                "options": {
                    "num_ctx": 8192 # Increase context window for code analysis
                }
            }
        )
        response_text = ollama_res.json().get('response', "I couldn't generate a response.")
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
        result = subprocess.run(['strings', '-n', '6', file_path], capture_output=True, text=True)
        lines = list(set(result.stdout.splitlines()))[:500]
        return lines
    except Exception as e:
        return {"error": str(e)}

@app.get("/binary/{name}/function/{addr}/decompile")
def decompile_function(name: str, addr: str):
    project_dir = "/data/projects"
    project_name = None
    
    if os.path.exists(project_dir):
        for f in os.listdir(project_dir):
            if f.endswith(".gpr"):
                project_name = f.replace(".gpr", "")
                break
            
    if not project_name:
        return {"error": "No Ghidra project found"}

    cmd = [
        "/ghidra/support/analyzeHeadless",
        project_dir,
        project_name,
        "-process", name,
        "-noanalysis",
        "-scriptPath", "/app/ghidra_scripts",
        "-postScript", "DecompileFunction.java", addr
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        
        lines = output.splitlines()
        code_lines = []
        capture = False
        for line in lines:
            if "DecompileFunction.java>" in line: capture = True; continue
            if capture: code_lines.append(line)
            
        return {"code": "\n".join(code_lines) if code_lines else "Decompilation produced no output."}
    except subprocess.TimeoutExpired:
        return {"error": "Decompilation timed out (30s)"}
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

@app.get("/binary/{name}/tree")
def get_program_tree(name: str):
    project_dir = "/data/projects"
    project_name = None
    
    if os.path.exists(project_dir):
        for f in os.listdir(project_dir):
            if f.endswith(".gpr"):
                project_name = f.replace(".gpr", "")
                break
            
    if not project_name:
        return {"error": "No Ghidra project found"}

    cmd = [
        "/ghidra/support/analyzeHeadless",
        project_dir,
        project_name,
        "-process", name,
        "-noanalysis",
        "-scriptPath", "/app/ghidra_scripts",
        "-postScript", "GetMemoryBlocks.java"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        
        json_str = ""
        capture = False
        for line in output.splitlines():
            if "GetMemoryBlocks.java>START" in line: capture = True; continue
            if "GetMemoryBlocks.java>END" in line: capture = False; break
            
            if capture:
                json_str += line
        
        if not json_str.strip():
            return {"error": "Script produced no output"}
            
        import json
        try:
            return json.loads(json_str) 
        except json.JSONDecodeError:
             return {"error": "Failed to decode script JSON output", "raw": json_str}

    except subprocess.TimeoutExpired:
        return {"error": "Tree fetch timed out (30s)"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/binary/{name}/symbols")
def get_symbols(name: str):
    project_dir = "/data/projects"
    project_name = None
    
    if os.path.exists(project_dir):
        for f in os.listdir(project_dir):
            if f.endswith(".gpr"):
                project_name = f.replace(".gpr", "")
                break
            
    if not project_name:
        return {"error": "No Ghidra project found"}

    cmd = [
        "/ghidra/support/analyzeHeadless",
        project_dir,
        project_name,
        "-process", name,
        "-noanalysis",
        "-scriptPath", "/app/ghidra_scripts",
        "-postScript", "GetSymbols.java"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        output = result.stdout
        
        json_str = ""
        capture = False
        for line in output.splitlines():
            if "GetSymbols.java>START" in line: capture = True; continue
            if "GetSymbols.java>END" in line: capture = False; break
            
            if capture:
                json_str += line
        
        if not json_str.strip():
            return {"error": "Script produced no output"}
            
        import json
        try:
            return json.loads(json_str) 
        except json.JSONDecodeError:
             return {"error": "Failed to decode script JSON output", "raw": json_str}

    except subprocess.TimeoutExpired:
        return {"error": "Symbols fetch timed out (45s)"}
    except Exception as e:
        return {"error": str(e)}

def run_headless_script(name: str, script: str, timeout: int = 45):
    project_dir = "/data/projects"
    project_name = None
    
    if os.path.exists(project_dir):
        for f in os.listdir(project_dir):
            if f.endswith(".gpr"):
                project_name = f.replace(".gpr", "")
                break
            
    if not project_name:
        return {"error": "No Ghidra project found"}

    cmd = [
        "/ghidra/support/analyzeHeadless",
        project_dir,
        project_name,
        "-process", name,
        "-noanalysis",
        "-scriptPath", "/app/ghidra_scripts",
        "-postScript", script
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout
        
        json_str = ""
        capture = False
        for line in output.splitlines():
            if f"{script}>START" in line: capture = True; continue
            if f"{script}>END" in line: capture = False; break
            
            if capture:
                json_str += line
        
        if not json_str.strip():
            return {"error": "Script produced no output"}
            
        import json
        try:
            return json.loads(json_str) 
        except json.JSONDecodeError:
             return {"error": "Failed to decode script JSON output", "raw": json_str}

    except subprocess.TimeoutExpired:
        return {"error": f"Script {script} timed out ({timeout}s)"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/binary/{name}/calltree")
def get_calltree(name: str):
    return run_headless_script(name, "GetCallTree.java")

@app.get("/binary/{name}/datatypes")
def get_datatypes(name: str):
    return run_headless_script(name, "GetDataTypes.java", timeout=60)

@app.get("/binary/{name}/bookmarks")
def get_bookmarks(name: str):
    return run_headless_script(name, "GetBookmarks.java")
