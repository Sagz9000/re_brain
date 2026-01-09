from .ghidra_ingestor import GhidraIngestor
from .malware_ingestor import MalwareTacticsIngestor
from .compiler_ingestor import CompilerIngestor
from .expert_ingestor import ExpertIngestor
import chromadb
import os

class KnowledgeManager:
    def __init__(self):
        host = os.getenv("CHROMA_HOST", "re-memory")
        port = os.getenv("CHROMA_PORT", "8000")
        self.client = chromadb.HttpClient(host=host, port=port)
        
        self.ghidra = GhidraIngestor(self.client)
        self.malware = MalwareTacticsIngestor(self.client)
        self.compiler = CompilerIngestor(self.client)
        self.expert = ExpertIngestor(self.client)

    def ingest_all(self, data_root="/data"):
        """Run all ingestion pipelines."""
        print("Starting Knowledge Graph Ingestion...")
        
        # 1. Ghidra Docs (Web)
        # self.ghidra.ingest() # Uncomment to run web scrape
        
        # 2. Malware Tactics
        self.malware.ingest(os.path.join(data_root, "malware"))
        
        # 3. Compiler Patterns
        self.compiler.ingest(os.path.join(data_root, "compiler_patterns"))
        
        # 4. Expert Knowledge
        self.expert.ingest(os.path.join(data_root, "expert"))
        
        print("Ingestion Complete.")
