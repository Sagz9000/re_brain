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
    
    BASE_URL = "https://ghidra.re/ghidra_docs/"
    COLLECTION_NAME = "ghidra_docs"

    def ingest(self, source_url: str = BASE_URL):
        """Scrapes the Ghidra docs site."""
        collection = self.client.get_or_create_collection(name=self.COLLECTION_NAME)
        
        # 1. Fetch Main Page to find links
        try:
            resp = requests.get(source_url)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.content, 'lxml')
        except Exception as e:
            logger.error(f"Failed to fetch {source_url}: {e}")
            return

        links = soup.find_all('a', href=True)
        ids, docs, metas = [], [], []
        
        count = 0
        for link in links:
            href = link['href']
            full_url = requests.compat.urljoin(source_url, href)
            
            if href.endswith('.pdf'):
                content = self._parse_pdf(full_url)
                type_tag = "pdf_manual"
            elif href.endswith('.html') and "api" in href: # Simple filter for now
                content = self._parse_html(full_url)
                type_tag = "api_doc"
            else:
                continue

            if content:
                # Basic chunking
                chunks = self.chunk_content(content)
                for i, chunk in enumerate(chunks):
                    ids.append(f"ghidra_{count}_{i}")
                    docs.append(chunk)
                    metas.append({
                        "source": "ghidra_docs",
                        "url": full_url,
                        "type": type_tag
                    })
                count += 1
                
                # Batch push
                if len(ids) >= 20:
                    collection.add(ids=ids, documents=docs, metadatas=metas)
                    ids, docs, metas = [], [], []

        if ids:
            collection.add(ids=ids, documents=docs, metadatas=metas)
            logger.info(f"Ingested {count} Ghidra documents.")

    def _parse_pdf(self, url):
        try:
            logger.info(f"Downloading PDF: {url}")
            resp = requests.get(url)
            with io.BytesIO(resp.content) as f:
                text = extract_text(f)
            return text
        except Exception as e:
            logger.error(f"Error parsing PDF {url}: {e}")
            return None

    def _parse_html(self, url):
        try:
            resp = requests.get(url)
            soup = BeautifulSoup(resp.content, 'lxml')
            # Remove nav/footer
            for tag in soup(['nav', 'footer', 'script', 'style']):
                tag.decompose()
            return soup.get_text(separator=' ', strip=True)
        except Exception as e:
            logger.error(f"Error parsing HTML {url}: {e}")
            return None

    def chunk_content(self, content: str):
        # Naive overlap chunking for now
        chunk_size = 1000
        overlap = 100
        return [content[i:i+chunk_size] for i in range(0, len(content), chunk_size-overlap)]
