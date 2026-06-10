"""
VulnScope v2 - CVE Similarity Engine
TF-IDF based semantic similarity search for CVEs
"""
import json
import math
import asyncio
import re
from collections import Counter
from database import get_db


def tokenize(text: str) -> list:
    """Simple tokenizer — lowercase, split on non-alphanumeric, remove short tokens"""
    text = text.lower()
    tokens = re.findall(r'[a-z0-9]{3,}', text)
    # Remove stopwords
    stopwords = {"the", "and", "for", "that", "this", "with", "from", "have",
                 "has", "been", "was", "are", "were", "will", "would", "could",
                 "should", "may", "might", "can", "shall", "its", "his", "her",
                 "their", "our", "your", "when", "where", "which", "what", "who",
                 "how", "not", "nor", "but", "some", "any", "all", "each", "every",
                 "about", "into", "over", "after", "before", "between"}
    return [t for t in tokens if t not in stopwords]


class CVEIndex:
    """In-memory TF-IDF index for CVE similarity search"""
    def __init__(self):
        self.cves = {}  # cve_id -> {description, tokens, ...}
        self.df = Counter()  # document frequency
        self.N = 0  # total documents
        self.built = False

    def add(self, cve_id: str, description: str, vendor: str = "", product: str = "",
            cwe: str = "", severity: str = "", cvss: float = 0):
        tokens = tokenize(description)
        # Add vendor/product tokens as extra signal
        if vendor:
            tokens.extend(tokenize(vendor))
        if product:
            tokens.extend(tokenize(product))

        unique_tokens = set(tokens)
        tf = Counter(tokens)

        self.cves[cve_id] = {
            "description": description[:300],
            "vendor": vendor,
            "product": product,
            "cwe": cwe,
            "severity": severity,
            "cvss": cvss,
            "tokens": unique_tokens,
            "tf": tf,
        }
        self.df.update(unique_tokens)
        self.N += 1

    def tfidf_vector(self, tokens: set, tf: Counter) -> dict:
        """Compute TF-IDF vector for a document"""
        vector = {}
        for token in tokens:
            tf_val = tf.get(token, 0)
            df_val = self.df.get(token, 1)
            idf = math.log((self.N + 1) / (df_val + 1)) + 1
            vector[token] = (1 + math.log(tf_val)) * idf if tf_val > 0 else 0
        return vector

    def cosine_similarity(self, vec1: dict, vec2: dict) -> float:
        """Cosine similarity between two sparse TF-IDF vectors"""
        dot = sum(vec1.get(k, 0) * vec2.get(k, 0) for k in set(vec1) & set(vec2))
        norm1 = math.sqrt(sum(v**2 for v in vec1.values()))
        norm2 = math.sqrt(sum(v**2 for v in vec2.values()))
        if norm1 == 0 or norm2 == 0:
            return 0
        return dot / (norm1 * norm2)

    def search(self, query: str, limit: int = 20, min_score: float = 0.05) -> list:
        """Search for similar CVEs by text query"""
        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        query_unique = set(query_tokens)
        query_tf = Counter(query_tokens)
        query_vec = self.tfidf_vector(query_unique, query_tf)

        results = []
        for cve_id, doc in self.cves.items():
            doc_vec = self.tfidf_vector(doc["tokens"], doc["tf"])
            score = self.cosine_similarity(query_vec, doc_vec)

            # Boost by severity
            if doc["severity"] == "CRITICAL":
                score *= 1.3
            elif doc["severity"] == "HIGH":
                score *= 1.1

            if score >= min_score:
                results.append({
                    "cve_id": cve_id,
                    "score": round(score, 4),
                    "description": doc["description"],
                    "vendor": doc["vendor"],
                    "severity": doc["severity"],
                    "cvss": doc["cvss"],
                })

        return sorted(results, key=lambda x: -x["score"])[:limit]

    def find_similar_cves(self, cve_id: str, limit: int = 10) -> list:
        """Find CVEs similar to a given CVE"""
        if cve_id not in self.cves:
            return []

        doc = self.cves[cve_id]
        doc_vec = self.tfidf_vector(doc["tokens"], doc["tf"])

        results = []
        for other_id, other_doc in self.cves.items():
            if other_id == cve_id:
                continue
            other_vec = self.tfidf_vector(other_doc["tokens"], other_doc["tf"])
            score = self.cosine_similarity(doc_vec, other_vec)

            if score > 0.1:
                results.append({
                    "cve_id": other_id,
                    "score": round(score, 4),
                    "description": other_doc["description"],
                    "severity": other_doc["severity"],
                    "vendor": other_doc["vendor"],
                })

        return sorted(results, key=lambda x: -x["score"])[:limit]

    def status(self) -> dict:
        return {"indexed": self.N, "unique_terms": len(self.df), "built": self.built}


# Global index instance
cve_index = CVEIndex()


async def build_index():
    """Build TF-IDF index from all CVEs in database"""
    global cve_index
    print("[Similarity] Building CVE index...")

    db = await get_db()
    rows = await db.execute("""
        SELECT cve_id, description, vendor, product, cwe_id, severity, cvss_score
        FROM cves ORDER BY published_date DESC LIMIT 5000
    """)
    cves = [dict(r) for r in await rows.fetchall()]
    await db.close()

    cve_index = CVEIndex()
    for cve in cves:
        cve_index.add(
            cve["cve_id"],
            cve.get("description", ""),
            cve.get("vendor", ""),
            cve.get("product", ""),
            cve.get("cwe_id", ""),
            cve.get("severity", "UNKNOWN"),
            cve.get("cvss_score") or 0,
        )

    cve_index.built = True
    print(f"[Similarity] Index built: {cve_index.N} CVEs, {cve_index.status()['unique_terms']} terms")


async def similarity_loop():
    """Periodic index rebuild"""
    await asyncio.sleep(120)
    while True:
        try:
            await build_index()
        except Exception as e:
            print(f"[Similarity] Error: {e}")
        await asyncio.sleep(3600)  # Hourly rebuild
