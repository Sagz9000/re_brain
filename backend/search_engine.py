import chromadb
from typing import List, Dict
import time
import sys

class SearchEngine:
    def __init__(self):
        import os
        host = os.getenv("CHROMA_HOST", "localhost")
        port = int(os.getenv("CHROMA_PORT", 8000))
        max_retries = 10
        for attempt in range(max_retries):
            try:
                self.client = chromadb.HttpClient(host=host, port=port)
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
    
    def search(self, query: str, top_k: int = 5, binary_context: str = None):
        """
        Performs a multi-stream search using Reciprocal Rank Fusion.
        """
        # Sources to query
        collections = {
            "ghidra_docs": self.client.get_or_create_collection("ghidra_docs"),
            "malware_tactics": self.client.get_or_create_collection("malware_tactics"),
            "compiler_patterns": self.client.get_or_create_collection("compiler_patterns"),
            "expert_knowledge": self.client.get_or_create_collection("expert_knowledge"),
            "binary_functions": self.client.get_or_create_collection("binary_functions"),
            "binary_analysis_findings": self.client.get_or_create_collection("binary_analysis_findings")
        }
        
        results_map = {}
        
        # 1. Query each collection
        for name, col in collections.items():
            try:
                # Apply filter for binary_analysis_findings to only show relevant binary info
                where_filter = None
                if name == "binary_analysis_findings" and binary_context:
                    where_filter = {"binary": binary_context}
                
                res = col.query(query_texts=[query], n_results=top_k, where=where_filter)
                
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

    def store_finding(self, binary_name: str, analysis_type: str, content: str, metadata: Dict = None):
        """Stores an AI analysis finding in the knowledge base."""
        try:
            col = self.client.get_or_create_collection("binary_analysis_findings")
            import uuid
            doc_id = f"{binary_name}_{analysis_type}_{uuid.uuid4().hex[:8]}"
            
            meta = {
                "source": "binary_analysis",
                "binary": binary_name,
                "type": analysis_type,
                "timestamp": str(time.time())
            }
            if metadata:
                # Flattens metadata for Chroma (only int/str/float allowed usually)
                for k, v in metadata.items():
                    if isinstance(v, (str, int, float, bool)):
                        meta[k] = v
                    else:
                        meta[k] = str(v)
            
            col.add(
                ids=[doc_id],
                documents=[content],
                metadatas=[meta]
            )
            print(f"Stored {analysis_type} finding for {binary_name}")
        except Exception as e:
            print(f"Failed to store finding: {e}")

    def delete_project_knowledge(self, binary_name: str):
        """Deletes all analysis findings related to a specific binary."""
        try:
            col = self.client.get_or_create_collection("binary_analysis_findings")
            col.delete(where={"binary": binary_name})
            print(f"Deleted knowledge for {binary_name}")
        except Exception as e:
            print(f"Failed to delete knowledge: {e}")

    def search(self, query: str, top_k: int = 5, binary_context: str = None):
        """
        Performs a multi-stream search using Reciprocal Rank Fusion.
        """
        # Sources to query
        collections = {
            "ghidra_docs": self.client.get_or_create_collection("ghidra_docs"),
            "malware_tactics": self.client.get_or_create_collection("malware_tactics"),
            "compiler_patterns": self.client.get_or_create_collection("compiler_patterns"),
            "expert_knowledge": self.client.get_or_create_collection("expert_knowledge"),
            "binary_functions": self.client.get_or_create_collection("binary_functions"),
            "binary_analysis_findings": self.client.get_or_create_collection("binary_analysis_findings")
        }
        
        results_map = {}
        
        # 1. Query each collection
        for name, col in collections.items():
            try:
                # Apply filter for binary_analysis_findings to only show relevant binary info
                where_filter = None
                if name == "binary_analysis_findings" and binary_context:
                    where_filter = {"binary": binary_context}
                
                res = col.query(query_texts=[query], n_results=top_k, where=where_filter)
                
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
