import chromadb
from typing import List, Dict
import time
import sys

class SearchEngine:
    def __init__(self):
        host = "re-memory" # In docker
        max_retries = 10
        for attempt in range(max_retries):
            try:
                self.client = chromadb.HttpClient(host=host, port=8000)
                self.client.heartbeat() # Verify connection
                print(f"Successfully connected to ChromaDB at {host}")
                return
            except Exception as e:
                print(f"Connection to ChromaDB failed (Attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    print("Max retries reached. Could not connect to ChromaDB.")
                    raise e
    
    def search(self, query: str, top_k: int = 5):
        """
        Performs a multi-stream search using Reciprocal Rank Fusion.
        """
        # Sources to query
        collections = {
            "ghidra_docs": self.client.get_or_create_collection("ghidra_docs"),
            "malware_tactics": self.client.get_or_create_collection("malware_tactics"),
            "compiler_patterns": self.client.get_or_create_collection("compiler_patterns"),
            "expert_knowledge": self.client.get_or_create_collection("expert_knowledge"),
            # "binary_functions": ... # Add when active analysis is ready
        }
        
        results_map = {}
        
        # 1. Query each collection
        for name, col in collections.items():
            try:
                # Basic query - in prod we'd generate sub-queries per domain
                res = col.query(query_texts=[query], n_results=top_k)
                
                # Normalize result structure
                if res['ids']:
                    ids = res['ids'][0]
                    docs = res['documents'][0]
                    metas = res['metadatas'][0]
                    
                    ranked_hits = []
                    for i in range(len(ids)):
                        ranked_hits.append({
                            "id": ids[i],
                            "content": docs[i],
                            "meta": metas[i],
                            "source": name,
                            "rank": i + 1
                        })
                    results_map[name] = ranked_hits
            except Exception as e:
                print(f"Search failed for {name}: {e}")

        # 2. Reciprocal Rank Fusion (RRF)
        # score = sum(1 / (k + rank))
        k = 60
        fused_scores = {}
        content_map = {}
        
        for source, hits in results_map.items():
            for hit in hits:
                doc_id = hit['id']
                if doc_id not in fused_scores:
                    fused_scores[doc_id] = 0
                    content_map[doc_id] = hit
                
                fused_scores[doc_id] += 1.0 / (k + hit['rank'])
                
        # Sort by fused score
        sorted_ids = sorted(fused_scores, key=fused_scores.get, reverse=True)
        
        final_results = []
        for doc_id in sorted_ids[:top_k*2]: # Return top merged results
            final_results.append(content_map[doc_id])
            
        return final_results

    def format_context(self, results: List[Dict]) -> str:
        """Formats RRF results into a text context for the LLM."""
        context = ""
        for item in results:
            source = item['meta'].get('source', 'unknown')
            content = item['content']
            context += f"--- Source: {source} ---\n{content}\n\n"
        return context
