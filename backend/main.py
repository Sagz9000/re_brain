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
    model: str = "qwen2.5:7b"
    history: Optional[List[dict]] = None

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
async def chat_endpoint(request: ChatRequest):
    if not search_engine:
        return {"error": "Search engine not initialized. Check logs."}
    
    log_event(f"User Query: {request.query}", source="User")
    
    # 1. Retrieve Context
    context_hits = search_engine.search(request.query)
    context_str = search_engine.format_context(context_hits)
    
    # Global Project State
    try:
        binaries = os.listdir(BINARIES_DIR)
        file_count = len(binaries)
        file_list_str = ", ".join(binaries)
    except:
        file_count = 0
        file_list_str = "None"
        
    system_context = f"Project State: {file_count} files analyzed: [{file_list_str}]."

    # Format History
    history_str = ""
    if request.history:
        for msg in request.history[-5:]:
            role = msg.get('role', 'user').upper()
            content = msg.get('content', '')
            history_str += f"{role}: {content}\n"

    final_prompt = (
        f"System Context: {system_context}\n\n"
        f"RAG Context:\n{context_str}\n\n"
        f"Chat History:\n{history_str}\n"
        "You are the RE Copilot. If the user wants to see data (hex, strings, functions, decompile), "
        "provide your analysis AND append a JSON block at the very end like this: \n"
        "UI_COMMAND: {\"action\": \"SWITCH_TAB\", \"tab\": \"hex\" | \"functions\" | \"strings\" | \"dashboard\" | \"graph\" | \"tree\", \"file\": \"filename\", \"address\": \"0x...\", \"function\": \"name\"}\n"
        f"User: {request.query}\n\nAnswer like a senior malware researcher."
    )

    try:
        ollama_res = requests.post(
            "http://re-ai:11434/api/generate",
            json={
                "model": request.model,
                "prompt": final_prompt,
                "stream": False
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
        "-scriptPath", "/ghidra/scripts",
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
        "-scriptPath", "/ghidra/scripts",
        "-postScript", "GetMemoryBlocks.java"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        
        blocks = []
        capture = False
        for line in output.splitlines():
            if "GetMemoryBlocks.java>START" in line: capture = True; continue
            if "GetMemoryBlocks.java>END" in line: capture = False; break
            
            if capture and "|" in line:
                parts = line.split("|")
                if len(parts) >= 6:
                    blocks.append({
                        "name": parts[0],
                        "start": parts[1],
                        "end": parts[2],
                        "size": parts[3],
                        "perms": parts[4],
                        "type": parts[5]
                    })
        
        return blocks
    except subprocess.TimeoutExpired:
        return {"error": "Tree fetch timed out (30s)"}
    except Exception as e:
        return {"error": str(e)}
