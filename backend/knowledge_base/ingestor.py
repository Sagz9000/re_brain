from abc import ABC, abstractmethod
from typing import List, Dict, Any

class KnowledgeIngestor(ABC):
    """Abstract base class for all knowledge stream ingestors."""
    
    def __init__(self, client):
        self.client = client
        
    @abstractmethod
    def ingest(self, source_path: str):
        """Ingests data from the given source path."""
        pass
        
    @abstractmethod
    def chunk_content(self, content: str) -> List[str]:
        """Splits content into appropriate chunks."""
        pass
