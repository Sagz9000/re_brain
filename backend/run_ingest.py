import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

from backend.knowledge_base.manager import KnowledgeManager

if __name__ == "__main__":
    # Use local 'data' folder
    data_path = os.path.join(os.getcwd(), "data")
    print(f"Triggering Ingestion using data in: {data_path}")

    # Set env vars for host access if not already set (fallback)
    if "CHROMA_HOST" not in os.environ:
        os.environ["CHROMA_HOST"] = "localhost"
    if "CHROMA_PORT" not in os.environ:
        os.environ["CHROMA_PORT"] = "8001"

    try:
        mgr = KnowledgeManager()
        mgr.ingest_all(data_root=data_path)
        print("✅ Ingestion Triggered Successfully.")
    except Exception as e:
        print(f"❌ Ingestion Failed: {e}")
