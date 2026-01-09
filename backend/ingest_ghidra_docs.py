import os
import glob
from bs4 import BeautifulSoup
import chromadb
from chromadb.config import Settings
import logging

# Configuration
DOCS_PATH = "/ghidra_docs/GhidraAPI_javadoc"  # Path inside container
CHROMA_HOST = os.getenv("CHROMA_HOST", "re-memory")
CHROMA_PORT = os.getenv("CHROMA_PORT", "8000")
COLLECTION_NAME = "ghidra_api"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_db():
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    return client

def parse_html_file(filepath):
    """Extracts text content and metadata from a Javadoc HTML file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            
            # Simple extraction strategy: Title + Main content
            title = soup.title.string if soup.title else os.path.basename(filepath)
            
            # Remove scripts and styles
            for script in soup(["script", "style"]):
                script.extract()
                
            text = soup.get_text(separator=' ', strip=True)
            
            # Metadata from file structure
            rel_path = os.path.relpath(filepath, DOCS_PATH)
            
            return {
                "content": text,
                "metadata": {
                    "source": "ghidra_api",
                    "filename": os.path.basename(filepath),
                    "path": rel_path
                }
            }
    except Exception as e:
        logger.error(f"Failed to parse {filepath}: {e}")
        return None

def ingest_docs():
    client = connect_db()
    
    # Create or get collection
    collection = client.get_or_create_collection(name=COLLECTION_NAME)
    
    logger.info(f"Scanning for docs in {DOCS_PATH}")
    files = glob.glob(os.path.join(DOCS_PATH, "**/*.html"), recursive=True)
    logger.info(f"Found {len(files)} HTML files.")

    batch_size = 50
    ids = []
    documents = []
    metadatas = []

    for i, file in enumerate(files):
        data = parse_html_file(file)
        if data:
            ids.append(f"doc_{i}")
            documents.append(data['content'][:8000]) # Chroma limit safeguard, better chunking needed later
            metadatas.append(data['metadata'])
            
            if len(ids) >= batch_size:
                collection.add(ids=ids, documents=documents, metadatas=metadatas)
                logger.info(f"Indexed batch {i}")
                ids, documents, metadatas = [], [], []

    if ids:
        collection.add(ids=ids, documents=documents, metadatas=metadatas)
        logger.info("Indexed final batch.")

if __name__ == "__main__":
    ingest_docs()
