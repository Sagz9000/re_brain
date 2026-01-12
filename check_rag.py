import chromadb
from chromadb.config import Settings
import os

# Configuration matching docker-compose
CHROMA_HOST = os.getenv("CHROMA_HOST", "re-memory2")
CHROMA_PORT = os.getenv("CHROMA_PORT", "8000")

def check_knowledgebase():
    try:
        # Connect to Chroma
        client = chromadb.HttpClient(host=CHROMA_HOST, port=int(CHROMA_PORT))
        print(f"Connected to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
        
        # List Collections
        collections = client.list_collections()
        if not collections:
            print("No collections found. The Knowledgebase is empty.")
            return

        print(f"\nFound {len(collections)} Collections:")
        total_docs = 0
        for col in collections:
            count = col.count()
            total_docs += count
            print(f"   [ {count:5} ] {col.name}")
            
            # Peel into a few examples if any exist
            if count > 0:
                try:
                    peek = col.peek(limit=1)
                    if peek['documents']:
                        content = peek['documents'][0][:100].replace('\n', ' ')
                        print(f"             Example: {content}...")
                except:
                    pass

        print(f"\nTotal Knowledgebase Size: {total_docs} vectors")
        
    except Exception as e:
        print(f"❌ Failed to connect to Knowledgebase: {e}")
        print("   If running locally, ensure you set env vars: CHROMA_HOST=localhost CHROMA_PORT=8001")

if __name__ == "__main__":
    check_knowledgebase()
