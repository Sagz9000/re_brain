import requests
import json

try:
    res = requests.post(
        "http://localhost:8005/chat", 
        json={"query": "What is the Program Tree?"}
    )
    data = res.json()
    print("Response Status:", res.status_code)
    
    if 'context_used' in data:
        print("\n--- Context Used ---")
        for ctx in data['context_used']:
            # Decode if needed, usually it's dict
            print(f"[Source: {ctx.get('source', 'unknown')}]")
            print(f"Content: {ctx.get('content', '')[:200]}...") # Show first 200 chars
            print("---")
    else:
        print("No 'context_used' found in response.")
        print(data)

except Exception as e:
    print(f"Error: {e}")
