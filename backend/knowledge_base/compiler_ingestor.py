import os
import glob
from .ingestor import KnowledgeIngestor

class CompilerIngestor(KnowledgeIngestor):
    """
    Ingests 'Rosetta Stone' pairs of C/C++ code and their compiled Assembly.
    Expects a directory structure like:
    /patterns
      /loop_unrolling
        source.c
        compiled_O3_x86.s
    """
    
    COLLECTION_NAME = "compiler_patterns"

    def ingest(self, source_path: str):
        collection = self.client.get_or_create_collection(name=self.COLLECTION_NAME)
        
        # We assume a specific filepair naming convention or folder structure
        # For simplicity, we'll look for subdirectories containing pairs
        
        ids, docs, metas = [], [], []
        count = 0

        for root, dirs, files in os.walk(source_path):
            c_files = [f for f in files if f.endswith('.c') or f.endswith('.cpp')]
            
            for c_file in c_files:
                base_name = os.path.splitext(c_file)[0]
                # Look for matching .s or .asm files
                asm_files = [f for f in files if f.startswith(base_name) and (f.endswith('.s') or f.endswith('.asm'))]
                
                if not asm_files:
                    continue

                # Read Source
                with open(os.path.join(root, c_file), 'r') as f:
                    c_content = f.read()

                for asm_file in asm_files:
                    # Parse optimization level from filename if poss (e.g. test_O3.s)
                    optim_level = "unknown"
                    if "O0" in asm_file: optim_level = "O0"
                    elif "O3" in asm_file: optim_level = "O3"
                    
                    with open(os.path.join(root, asm_file), 'r') as f:
                        asm_content = f.read()

                    # Create a combined document explaining the relationship
                    # We might want to embed the ASM primarily, but query with "What is this ASM?"
                    # So the document should be the ASM, and the metadata/context is the C source.
                    
                    ids.append(f"pat_{count}")
                    docs.append(f"Assembly Pattern ({optim_level}):\n{asm_content}\n\nGenerated from C Source:\n{c_content}")
                    metas.append({
                        "source": "compiler_pattern",
                        "optimization": optim_level,
                        "c_source": c_content[:500] # Store snippet in meta
                    })
                    count += 1

        if ids:
            collection.add(ids=ids, documents=docs, metadatas=metas)
            print(f"Ingested {count} compiler patterns.")

    def chunk_content(self, content: str):
        return [content] # Patterns are usually small enough to be single chunks
