import os
import requests
import io
from bs4 import BeautifulSoup
from pdfminer.high_level import extract_text
from .ingestor import KnowledgeIngestor
import logging

logger = logging.getLogger(__name__)

class GhidraIngestor(KnowledgeIngestor):
    """Ingests Ghidra documentation from the official website and PDFs."""
    
    START_URLS = [
        "https://ghidra.re/ghidra_docs/api/index.html",
        "https://ghidra.re/ghidra_docs/api/help-doc.html",
        "https://ghidra.re/ghidra_docs/api/overview-tree.html"
    ]
    COLLECTION_NAME = "ghidra_docs"

    def ingest(self, source_url: str = None):
        """Scrapes the Ghidra docs site with crawling."""
        collection = self.client.get_or_create_collection(name=self.COLLECTION_NAME)
        
        visited = set()
        to_visit = [source_url] if source_url else self.START_URLS.copy()
        
        max_docs = 2000 # Increased limit
        count = 0
        
        ids, docs, metas = [], [], []

        print(f"Starting crawl. Initial queue size: {len(to_visit)}")

        while to_visit and count < max_docs:
            url = to_visit.pop(0)
            norm_url = url.split('#')[0]
            if norm_url in visited: continue
            visited.add(norm_url)
            
            if count % 10 == 0:
                print(f"Progress: {count}/{max_docs} docs. Queue size: {len(to_visit)}")
            
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200:
                    print(f"Skipping {url} (Status {resp.status_code})")
                    continue
                
                if url.endswith('.pdf'):
                    content = self._parse_pdf_content(resp.content)
                    type_tag = "pdf_manual"
                    soup = None
                else:
                    soup = BeautifulSoup(resp.content, 'lxml')
                    content = self._extract_text(soup)
                    type_tag = "api_doc"

                if content and len(content.strip()) > 100:
                    chunks = self.chunk_content(content)
                    for i, chunk in enumerate(chunks):
                        ids.append(f"ghidra_{count}_{i}")
                        docs.append(chunk)
                        metas.append({
                            "source": "ghidra_docs",
                            "url": url,
                            "type": type_tag
                        })
                    count += 1
                    
                    if len(ids) >= 50:
                        collection.add(ids=ids, documents=docs, metadatas=metas)
                        ids, docs, metas = [], [], []
                else:
                    print(f"No content found for {url}")

                # Find new links
                if soup:
                    new_links = 0
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        # Filter out mailto, javascript, external
                        if href.startswith(('mailto:', 'javascript:', 'http')):
                            if not href.startswith("https://ghidra.re/ghidra_docs/api/"):
                                continue
                        
                        full_url = requests.compat.urljoin(url, href).split('#')[0]
                        
                        if full_url.startswith("https://ghidra.re/ghidra_docs/api/"):
                            if full_url not in visited and full_url not in to_visit:
                                if full_url.endswith('.html') or full_url.endswith('.pdf'):
                                    to_visit.append(full_url)
                                    new_links += 1
                    # print(f"Found {new_links} new links on {url}")

            except Exception as e:
                print(f"Error crawling {url}: {e}")

        if ids:
            collection.add(ids=ids, documents=docs, metadatas=metas)
            
        print(f"✅ Ingestion complete. Processed {count} documents.")

    def _parse_pdf_content(self, raw_content):
        try:
            with io.BytesIO(raw_content) as f:
                text = extract_text(f)
            return text
        except Exception as e:
            logger.error(f"Error parsing PDF: {e}")
            return None

    def _extract_text(self, soup):
        try:
            # Remove nav/footer to keep context relevant
            for tag in soup(['nav', 'footer', 'script', 'style', 'header']):
                tag.decompose()
            return soup.get_text(separator=' ', strip=True)
        except Exception as e:
            logger.error(f"Error extracting text from soup: {e}")
            return None

    def chunk_content(self, content: str):
        # Naive overlap chunking
        chunk_size = 1200
        overlap = 200
        return [content[i:i+chunk_size] for i in range(0, len(content), chunk_size-overlap)]
