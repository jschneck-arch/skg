import unittest
from dataclasses import dataclass

from skg.resonance.mcp_threading import MCPThreadingConfig, MCPThreadingOrchestrator


@dataclass
class _AdapterRec:
    adapter_name: str
    domain: str
    wickets_covered: list[str]
    evidence_sources: list[str]


class _FakeEngine:
    def surface(self, query: str, k_each: int = 3):
        return {
            "query": query,
            "wickets": [
                {"score": 0.8, "record": {"wicket_id": "HO-01", "label": "ssh_open"}},
            ],
            "adapters": [
                {"score": 0.7, "record": {"adapter_name": "ssh_collect"}},
            ],
            "domains": [
                {"score": 0.6, "record": {"domain": "host"}},
            ],
            "corpus": [
                {"score": 0.5, "record": {"source_kind": "help", "source_ref": "ssh"}},
            ],
        }

    def query_adapters(self, text: str, k: int = 8):
        return [
            (
                _AdapterRec(
                    adapter_name="ssh_collect",
                    domain="host",
                    wickets_covered=["HO-01"],
                    evidence_sources=["ss -tulpn"],
                ),
                0.91,
            )
        ]


class _FakeAssistant:
    def __init__(self):
        self.last_query = ""

    def ask(self, query: str, prefer=None, k_each=None, theta=None):
        self.last_query = query
        return {
            "query": query,
            "route": prefer or "fast",
            "route_reason": "fake",
            "model_used": "fake-model",
            "models_attempted": ["fake-model"],
            "num_predict": 64,
            "fallback_used": False,
            "latency_s": 0.01,
            "context_counts": {"wickets": 1, "adapters": 1, "domains": 1, "corpus": 1},
            "context_preview": [],
            "theta": theta or "",
            "response": "Use ssh_collect first, then verify.",
        }

    def status(self):
        return {"backend": {"available": True, "selected_model": "fake-model"}}


class MCPThreadingTests(unittest.TestCase):
    def test_thread_returns_layered_result(self):
        assistant = _FakeAssistant()
        orchestrator = MCPThreadingOrchestrator(
            _FakeEngine(),
            assistant=assistant,
            config=MCPThreadingConfig(
                enabled=True,
                capability_scan=False,
                k_each=3,
                adapter_k=4,
                max_workers=2,
                advisory_only=True,
            ),
        )

        result = orchestrator.thread("check ssh exposure", theta="runtime")
        self.assertEqual(result["source_of_truth"], "skg.resonance")
        self.assertEqual(result["execution"]["mode"], "layered_mcp_threading")
        self.assertIn("memory", result["threads"])
        self.assertIn("instruments", result["threads"])
        self.assertIn("instrument_decision", result["threads"])
        self.assertIn("reasoner", result["threads"])
        self.assertIn("verification", result["threads"])
        self.assertEqual(result["threads"]["instruments"]["count"], 1)
        self.assertEqual(result["threads"]["instrument_decision"]["selected_adapters"], ["ssh_collect"])
        self.assertIn("selected_instruments: ssh_collect", assistant.last_query)

    def test_verification_detects_known_instrument_mentions(self):
        orchestrator = MCPThreadingOrchestrator(
            _FakeEngine(),
            assistant=_FakeAssistant(),
            config=MCPThreadingConfig(enabled=True, capability_scan=False),
        )
        result = orchestrator.thread("probe host", theta="runtime")
        verification = result["threads"]["verification"]
        self.assertTrue(verification["mentions_known_instrument"])
        self.assertIn("ssh_collect", verification["mentioned_instruments"])
        self.assertTrue(verification["mentions_selected_instrument"])
        self.assertIn("ssh_collect", verification["mentioned_selected_instruments"])

    def test_status_exposes_source_of_truth(self):
        orchestrator = MCPThreadingOrchestrator(
            _FakeEngine(),
            assistant=_FakeAssistant(),
            config=MCPThreadingConfig(enabled=True, capability_scan=False, max_workers=5),
        )
        status = orchestrator.status()
        self.assertEqual(status["source_of_truth"], "skg.resonance")
        self.assertEqual(status["config"]["max_workers"], 5)


if __name__ == "__main__":
    unittest.main()
