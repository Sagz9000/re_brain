import os
import glob
from .ingestor import KnowledgeIngestor

class ExpertIngestor(KnowledgeIngestor):
    """
    Ingests CTF writeups and manual extracts.
    Expects unstructured text or markdown files.
    """
    
    COLLECTION_NAME = "expert_knowledge"

    def ingest(self, source_path: str):
        collection = self.client.get_or_create_collection(name=self.COLLECTION_NAME)
        
        files = glob.glob(os.path.join(source_path, "**/*"), recursive=True)
        # Filter for text-readable files
        files = [f for f in files if f.endswith('.md') or f.endswith('.txt')]

        ids, docs, metas = [], [], []
        
        for i, fpath in enumerate(files):
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Tagging logic could be smarter (regex for "CTF", "Writeup")
                category = "general"
                if "ctf" in fpath.lower(): category = "ctf_writeup"
                elif "manual" in fpath.lower(): category = "instruction_manual"

                chunks = self.chunk_content(content)
                for j, chunk in enumerate(chunks):
                    ids.append(f"exp_{i}_{j}")
                    docs.append(chunk)
                    metas.append({
                        "source": "expert_writeup",
                        "category": category,
                        "filename": os.path.basename(fpath)
                    })
            except Exception as e:
                print(f"Skipping {fpath}: {e}")

        if docs:
            collection.add(ids=ids, documents=docs, metadatas=metas)
            print(f"Ingested {len(docs)} expert knowledge chunks.")

    def chunk_content(self, content: str):
        # Paragraph splitting
        return [p for p in content.split('\n\n') if len(p) > 100]
