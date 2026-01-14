from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict
import os
from debug_session import DebugSession
import logging

router = APIRouter(prefix="/debug", tags=["debugger"])
logger = logging.getLogger(__name__)

# Global session store: binary_name -> DebugSession
# Limitation: One session per binary per server instance for now. 
# Ideally should be session_id based, but UI context is file-based.
sessions: Dict[str, DebugSession] = {}

class DebugRequest(BaseModel):
    binary_name: str
    command: Optional[str] = None
    address: Optional[str] = None
    steps: Optional[int] = 1

@router.post("/start")
def start_debug(req: DebugRequest):
    bin_path = f"/data/binaries/{req.binary_name}"
    if not os.path.exists(bin_path):
        raise HTTPException(status_code=404, detail="Binary not found")
    
    if req.binary_name in sessions:
        sessions[req.binary_name].stop()
        
    try:
        session = DebugSession(bin_path)
        # Auto-start execution
        res = session.start()
        sessions[req.binary_name] = session
        return {"status": "started", "output": res}
    except Exception as e:
        logger.error(f"Failed to start debug: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
def stop_debug(req: DebugRequest):
    if req.binary_name in sessions:
        sessions[req.binary_name].stop()
        del sessions[req.binary_name]
    return {"status": "stopped"}

@router.post("/step")
def step_debug(req: DebugRequest):
    if req.binary_name not in sessions:
        raise HTTPException(status_code=400, detail="Session not active")
    
    session = sessions[req.binary_name]
    # Default to step instruction
    res = session.step_into()
    return {"status": "stepped", "output": res}

@router.post("/next")
def next_debug(req: DebugRequest):
    if req.binary_name not in sessions:
        raise HTTPException(status_code=400, detail="Session not active")
    
    session = sessions[req.binary_name]
    res = session.step_over()
    return {"status": "next", "output": res}

@router.post("/continue")
def continue_debug(req: DebugRequest):
    if req.binary_name not in sessions:
        raise HTTPException(status_code=400, detail="Session not active")
    
    session = sessions[req.binary_name]
    res = session.continue_exec()
    return {"status": "running", "output": res}

@router.post("/break")
def break_debug(req: DebugRequest):
    if req.binary_name not in sessions:
        raise HTTPException(status_code=400, detail="Session not active")
    if not req.address:
        raise HTTPException(status_code=400, detail="Address required")
        
    session = sessions[req.binary_name]
    res = session.add_breakpoint(req.address)
    return {"status": "breakpoint_set", "output": res}

@router.post("/cmd")
def raw_cmd(req: DebugRequest):
    if req.binary_name not in sessions:
        raise HTTPException(status_code=400, detail="Session not active")
    if not req.command:
        raise HTTPException(status_code=400, detail="Command required")
        
    session = sessions[req.binary_name]
    res = session.raw_command(req.command)
    return {"status": "executed", "output": res}

@router.get("/state/{binary_name}")
def get_state(binary_name: str):
    if binary_name not in sessions:
        return {"active": False}
    
    session = sessions[binary_name]
    if not session.active:
        return {"active": False}
        
    return {
        "active": True,
        "registers": session.get_registers(),
        "stack": session.get_stack()
    }

@router.get("/memory/{binary_name}/{address}")
def get_memory(binary_name: str, address: str):
    if binary_name not in sessions:
        raise HTTPException(status_code=400, detail="Session not active")
        
    session = sessions[binary_name]
    mem = session.get_memory(address)
    return {"memory": mem}
