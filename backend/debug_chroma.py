import chromadb
import traceback
import sys

print(f"ChromaDB Client Version: {chromadb.__version__}")
try:
    c = chromadb.HttpClient(host='re-memory', port=8000)
    print("Client created. Attempting heartbeat...")
    val = c.heartbeat()
    print(f"Heartbeat: {val}")
    print("Success")
except:
    traceback.print_exc()
