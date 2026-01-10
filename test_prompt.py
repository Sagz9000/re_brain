import requests
import json

try:
    res = requests.post(
        "http://localhost:8005/chat", 
        json={"query": "Analyze the main function"}
    )
    data = res.json()
    print("Response Status:", res.status_code)
    print("\n--- AI Response ---")
    print(data.get('response', 'No response'))
    print("\n--- Context Sources ---")
    if 'context_used' in data:
        sources = set([ctx.get('source', 'unknown') for ctx in data['context_used']])
        print(f"Used {len(data['context_used'])} context chunks from: {sources}")

except Exception as e:
    print(f"Error: {e}")
