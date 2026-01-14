
import re
import json

def extract_json_from_ghidra_output(output: str):
    json_str = ""
    capture = False
    
    print("--- DEBUG: Starting Extraction ---")
    
    # Heuristic: collect lines between markers
    for line in output.splitlines():
        if "JSON_START" in line or ">START" in line:
            capture = True
            print(f"DEBUG: Found start marker in line: '{line}'")
            continue
        if "JSON_END" in line or ">END" in line:
            capture = False
            print(f"DEBUG: Found end marker in line: '{line}'")
            break
        if capture:
            # Robustly strip Ghidra log noise (e.g. "INFO  GetSymbols.java> {")
            # We only strip if the line STARTS with a level and has a script marker
            
            # 1. Strip script prefixes "INFO ScriptName> "
            clean_line = re.sub(r'^\s*(?:INFO|WARN|ERROR).*?>\s*', '', line).strip()
            
            # 2. Filter out raw system logs that interrupted the JSON stream
            if clean_line.startswith(("INFO ", "WARN ", "ERROR ", "REPORT ", "DEBUG ")):
                print(f"DEBUG: Skipped interruptive log: '{clean_line}'")
                continue
                
            # print(f"DEBUG: Kept line: '{clean_line}' (Original: '{line}')")
            json_str += clean_line + "\n"
    
    print(f"--- DEBUG: Extracted String Length: {len(json_str)} ---")
    # print(f"DEBUG: Extracted Content:\n{json_str}")

    if not json_str.strip():
        print("DEBUG: Extracted string is empty.")
        return None

    # Final cleanup: find the actual JSON bounds to ignore any remaining trailing/leading noise
    try:
        # Try direct load first
        return json.loads(json_str) 
    except json.JSONDecodeError as e:
        print(f"DEBUG: Direct JSON load failed: {e}")
        # If nested markers or partial logs, try to find the first { or [
        start_idx = -1
        if "{" in json_str: start_idx = json_str.find("{")
        if "[" in json_str and (start_idx == -1 or json_str.find("[") < start_idx):
            start_idx = json_str.find("[")
            
        if start_idx != -1:
            try:
                candidate = json_str[start_idx:]
                return json.loads(candidate)
            except Exception as e2:
                print(f"DEBUG: Candidate load failed: {e2}")
                pass
                
    return None

# Test Data from User Logs
log_output = """
INFO  HEADLESS: execution starts (HeadlessAnalyzer)  

INFO  Opening existing project: /data/projects/flare1 (HeadlessAnalyzer)  

INFO  Opening project: /data/projects/flare1 (HeadlessProject)  

INFO  REPORT: Processing read-only project file: /challenge1.exe (HeadlessAnalyzer)  

INFO  REPORT: Execute script: GetSymbols.java  (HeadlessAnalyzer)  

INFO  SCRIPT: /ghidra_scripts/GetSymbols.java (HeadlessAnalyzer)  

INFO  GetSymbols.java> JSON_START (GhidraScript)  

INFO  GetSymbols.java> {

  "imports": [

    {

      "address": "EXTERNAL:00000001",

      "name": "ReadFile"

    },

    {

      "address": "EXTERNAL:00000002",

      "name": "QueryPerformanceCounter"

    },
    
    {
       "dummy": "last"
    }
  ]
}

INFO  GetSymbols.java> JSON_END (GhidraScript)
"""

result = extract_json_from_ghidra_output(log_output)
if result:
    print("SUCCESS: JSON Parsed Correctly")
    print(json.dumps(result, indent=2))
else:
    print("FAILURE: Could not extract JSON")
