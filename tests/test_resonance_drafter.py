import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, "/opt/skg")

from skg.resonance.drafter import draft_catalog


class _FakeEngine:
    def __init__(self, draft_dir: Path):
        self._draft_dir = draft_dir

    def surface(self, query: str, k_each: int = 4):
        return {"query": query, "wickets": [], "adapters": [], "domains": []}

    def save_draft(self, domain_name: str, catalog: dict) -> Path:
        out = self._draft_dir / f"{domain_name}.json"
        out.write_text("{}", encoding="utf-8")
        return out


class ResonanceDrafterTests(unittest.TestCase):
    def test_draft_catalog_uses_ollama_backend_without_api_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = _FakeEngine(Path(tmpdir))
            catalog = {
                "domain": "ai_target",
                "wickets": {"AI-01": {"label": "service_reachable"}},
                "attack_paths": {"ai_llm_extract_v1": {"required_wickets": ["AI-01"]}},
            }

            with patch("skg.resonance.ollama_backend.OllamaBackend.available", return_value=True), \
                 patch("skg.resonance.ollama_backend.OllamaBackend.model", return_value="tinyllama:latest"), \
                 patch("skg.resonance.ollama_backend.OllamaBackend.draft_catalog", return_value=(catalog, [])):
                result = draft_catalog(engine, "ai_target", "AI service attack surface")

        self.assertEqual(result["backend"], "ollama")
        self.assertEqual(result["model"], "tinyllama:latest")
        self.assertEqual(result["catalog"]["domain"], "ai_target")
        self.assertEqual(result["validation_errors"], [])


if __name__ == "__main__":
    unittest.main()
