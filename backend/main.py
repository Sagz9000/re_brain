from fastapi import FastAPI
from pydantic import BaseModel
import logging
import sys
import time

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from search_engine import SearchEngine
except ImportError as e:
    logger.error(f"Failed to import SearchEngine: {e}")
    SearchEngine = None

app = FastAPI(title="reAIghidra API", version="0.1.0")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins for dev (fixes localhost ports mismatch)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    query: str
    model: str = "qwen2.5:7b" 

# Global SearchEngine instance
search_engine = None
try:
    if SearchEngine:
        search_engine = SearchEngine()
        logger.info("Search Engine initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize SearchEngine: {e}")


@app.get("/")
def read_root():
    return {"status": "online", "service": "reAIghidra Backend"}

# Activity Log
activity_logs = []

def log_event(message, source="System"):
    timestamp = time.strftime("%H:%M:%S")
    event = {"time": timestamp, "message": message, "source": source}
    activity_logs.append(event)
    logger.info(f"[{source}] {message}")
    # Keep only last 100
    if len(activity_logs) > 100:
        activity_logs.pop(0)

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
        
    # [NEW] Add a specific summary document for the file itself
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
    
    # [NEW] Global Project State
    try:
        binaries = os.listdir(BINARIES_DIR)
        file_count = len(binaries)
        file_list_str = ", ".join(binaries)
    except:
        file_count = 0
        file_list_str = "None"
        
    system_context = f"Project State: {file_count} files analyzed: [{file_list_str}]."

    # 2. Call LLM (Ollama)
    import requests
    try:
        ollama_res = requests.post(
            "http://re-ai:11434/api/generate",
            json={
                "model": request.model,
                "prompt": f"System Context: {system_context}\n\nRAG Context:\n{context_str}\n\nQuestion: {request.query}\n\nAnswer concisely as a reverse engineer expert. Use the System Context for high-level project questions.",
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

# Validates directory existence
PROJECTS_DIR = "/data/projects"
JOBS_PENDING_DIR = "/data/jobs/pending"
BINARIES_DIR = "/data/binaries"

import os
import json
import uuid
import shutil
from fastapi import File, UploadFile, Form

# Ensure directories exist
for d in [PROJECTS_DIR, JOBS_PENDING_DIR, BINARIES_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    is_new_project: bool = Form(...)
):
    try:
        # Ensure directory exists
        os.makedirs(BINARIES_DIR, exist_ok=True)
        
        # 1. Save File
        file_location = f"{BINARIES_DIR}/{file.filename}"
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
            
        # 2. Create Job Ticket
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
            hex_str = data.hex()
            return {
                "hex": hex_str,
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
        res = collection.get(
            where={"binary": name}
        )
        
        funcs = []
        if res['ids']:
            for i, doc in enumerate(res['documents']):
                meta = res['metadatas'][i]
                if meta.get('type') == 'function':
                   content = doc
                   try:
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
