import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from skg.resonance.embedder import TFIDFEmbedder
from skg.resonance.engine import ResonanceEngine
from skg.resonance.memory import CorpusMemory


class ResonanceCorpusMemoryTests(unittest.TestCase):
    def test_store_and_query_corpus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with patch("skg.resonance.engine.make_embedder", return_value=TFIDFEmbedder()):
                engine = ResonanceEngine(base)
                engine.boot()

            text = "ssh --help explains identity file and username flags"
            rec = CorpusMemory(
                record_id="corpus::test1",
                source_kind="help",
                source_ref="ssh",
                title="ssh --help",
                text=text,
                tags=["help", "ssh"],
                domain="local_runtime",
                embed_text=CorpusMemory.make_embed_text(
                    source_kind="help",
                    source_ref="ssh",
                    title="ssh --help",
                    text=text,
                    tags=["help", "ssh"],
                    domain="local_runtime",
                ),
            )

            self.assertTrue(engine.store_corpus(rec))
            self.assertFalse(engine.store_corpus(rec))

            results = engine.query_corpus("how to set ssh identity file", k=3)
            self.assertTrue(results)
            self.assertEqual(results[0][0].source_ref, "ssh")

            surfaced = engine.surface("ssh identity file", k_each=2)
            self.assertIn("corpus", surfaced)
            self.assertGreaterEqual(len(surfaced["corpus"]), 1)


if __name__ == "__main__":
    unittest.main()
