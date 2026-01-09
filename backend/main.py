from fastapi import FastAPI
from pydantic import BaseModel
import logging
import sys

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from search_engine import SearchEngine
except ImportError as e:
    logger.error(f"Failed to import SearchEngine: {e}")
    SearchEngine = None

app = FastAPI(title="reAIghidra API", version="0.1.0")

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

@app.post("/chat")
def chat_endpoint(request: ChatRequest):
    if not search_engine:
        return {"error": "Search engine not initialized. Check logs."}
    
    # 1. Retrieve Context via RRF
    context_hits = search_engine.search(request.query)
    context_str = search_engine.format_context(context_hits)
    
    # 2. Construct Prompt
    system_prompt = "You are a specialized Reverse Engineering Assistant. Use the provided context to answer the user's question about the binary."
    user_prompt = f"Context:\n{context_str}\n\nQuestion: {request.query}"
    
    # 3. Call LLM (Ollama)
    # Placeholder: In prod, use requests.post to re-ai:11434/api/generate
    
    return {
        "response": f"[Simulated LLM Answer] Based on the context...", 
        "context_used": context_hits,
        "model": request.model
    }

@app.post("/ingest/binary")
def ingest_binary(data: dict):
    # data expects {"functions": [...]}
    funcs = data.get("functions", [])
    print(f"Received {len(funcs)} functions for ingestion.")
    
    # TODO: Pass to a BinaryIngestor class to chunk and properly index in Chroma
    # linking them to the Knowledge Graph
    
    return {"status": "received", "count": len(funcs)}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
