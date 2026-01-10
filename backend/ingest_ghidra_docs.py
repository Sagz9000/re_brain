import requests
from bs4 import BeautifulSoup
import chromadb
import sys
import os

# Ensure we can import SearchEngine
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from search_engine import SearchEngine

def ingest_ghidra_docs():
    print("Initializing Search Engine...")
    se = SearchEngine()
    if not se.client:
        print("Failed to connect to DB.")
        return

    collection = se.client.get_or_create_collection("ghidra_docs")
    
    # Target URLs
    urls = [
        "https://ghidra.re/ghidra_docs/api/help-doc.html#tree",
        "https://ghidra.re/ghidra_docs/api/overview-tree.html",
        "https://ghidra.re/ghidra_docs/api/index.html"
    ]
    
    documents = []
    ids = []
    metadatas = []
    
    print("Scraping URLs...")
    for url in urls:
        try:
            print(f"Fetching {url}...")
            res = requests.get(url)
            if res.status_code != 200:
                print(f"Failed to fetch {url}")
                continue
            
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # Extract main content
            # The structure varies, but generally text in <main> or <body>
            main_content = soup.find('main') or soup.body
            if not main_content:
                continue
                
            text = main_content.get_text(separator='\n', strip=True)
            
            # Simple chunking by paragraphs or length
            chunks = []
            chunk_size = 1000
            for i in range(0, len(text), chunk_size):
                chunks.append(text[i:i+chunk_size])
            
            for i, chunk in enumerate(chunks):
                doc_id = f"{url}_{i}"
                ids.append(doc_id)
                documents.append(chunk)
                metadatas.append({"source": "ghidra_docs", "url": url, "chunk": i})
                
        except Exception as e:
            print(f"Error processing {url}: {e}")
            
    if ids:
        print(f"Upserting {len(ids)} chunks to 'ghidra_docs' collection...")
        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        print("Ingestion complete.")
    else:
        print("No content found to ingest.")

if __name__ == "__main__":
    ingest_ghidra_docs()
