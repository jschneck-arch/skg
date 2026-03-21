import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, "/opt/skg")

from skg.resonance.ollama_backend import OllamaBackend


class OllamaBackendConfigTests(unittest.TestCase):
    def test_backend_reads_model_url_and_temperature_from_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            (config_dir / "skg_config.yaml").write_text(
                "\n".join([
                    "resonance:",
                    "  ollama:",
                    "    url: http://127.0.0.1:22444",
                    "    model: tinyllama:latest",
                    "    temperature: 0.25",
                ]),
                encoding="utf-8",
            )

            with patch("skg.core.paths.SKG_CONFIG_DIR", config_dir), \
                 patch("skg.core.paths.SKG_STATE_DIR", config_dir / "state"):
                backend = OllamaBackend()

            self.assertEqual(backend.url, "http://127.0.0.1:22444")
            self.assertEqual(backend._model, "tinyllama:latest")
            self.assertEqual(backend.temperature, 0.25)


if __name__ == "__main__":
    unittest.main()
