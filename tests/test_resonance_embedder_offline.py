import unittest
from unittest.mock import patch

from skg.resonance.embedder import TFIDFEmbedder, make_embedder


class ResonanceEmbedderOfflineTests(unittest.TestCase):
    def test_make_embedder_offline_env_forces_tfidf(self):
        with patch.dict("os.environ", {"SKG_RESONANCE_OFFLINE": "1"}, clear=False):
            emb = make_embedder()
        self.assertIsInstance(emb, TFIDFEmbedder)


if __name__ == "__main__":
    unittest.main()
