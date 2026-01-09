# AnalyzeAndIngest.py
# Decompiles all functions in the current program and sends them to the reAIghidra RAG API.
# @category AI_Analysis
# @keybinding 
# @menupath Tools.AI.Analyze and Ingest
# @toolbar 

import ghidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json
import urllib2
import os

# Configuration
API_URL = os.getenv("API_URL", "http://re-api:8000/ingest/binary")

def get_decompiler_interface():
    di = DecompInterface()
    di.openProgram(currentProgram)
    return di

def send_to_api(payload):
    try:
        req = urllib2.Request(API_URL)
        req.add_header('Content-Type', 'application/json')
        response = urllib2.urlopen(req, json.dumps(payload))
        print("Successfully sent batch to API: " + str(response.getcode()))
    except Exception as e:
        print("Error sending to API: " + str(e))

def analyze_and_ingest():
    print("Starting AI Ingestion for: " + currentProgram.getName())
    
    di = get_decompiler_interface()
    monitor = ConsoleTaskMonitor()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    
    batch = []
    batch_size = 10
    
    for func in functions:
        if monitor.isCancelled():
            break
            
        print("Processing: " + func.getName())
        
        # Decompile
        res = di.decompileFunction(func, 60, monitor)
        if not res.decompileCompleted():
            print("Failed to decompile: " + func.getName())
            continue
            
        decompiled_c = res.getDecompiledFunction().getC()
        
        # Get Assembly (Naive approach: iterate instructions)
        asm_lines = []
        inst = currentProgram.getListing().getInstructionAt(func.getEntryPoint())
        while inst is not None and func.getBody().contains(inst.getAddress()):
            asm_lines.append(str(inst))
            inst = inst.getNext()
            
        asm_content = "\n".join(asm_lines)
        
        func_data = {
            "program_name": currentProgram.getName(),
            "function_name": func.getName(),
            "entry_point": str(func.getEntryPoint()),
            "decompiled_code": decompiled_c,
            "assembly": asm_content
        }
        
        batch.append(func_data)
        
        if len(batch) >= batch_size:
            send_to_api({"functions": batch})
            batch = []
            
    if len(batch) > 0:
        send_to_api({"functions": batch})
        
    print("Ingestion Complete.")

if __name__ == "__main__":
    analyze_and_ingest()
