
import requests
import json

url = "http://localhost:8005/chat"
payload = {
    "query": "What internal functions does the binary have?",
    "model": "qwen2.5:7b"
}

try:
    response = requests.post(url, json=payload)
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
