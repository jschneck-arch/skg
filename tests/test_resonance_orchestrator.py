import unittest

from skg.resonance.orchestrator import LayeredAssistant, OrchestratorConfig, PromptRouter


class _FakeEngine:
    def surface(self, query: str, k_each: int = 3):
        return {
            "query": query,
            "wickets": [
                {
                    "score": 0.92,
                    "record": {
                        "wicket_id": "HO-01",
                        "label": "ssh_open",
                        "description": "OpenSSH listens on port 22",
                    },
                }
            ],
            "adapters": [
                {
                    "score": 0.81,
                    "record": {
                        "adapter_name": "ssh_collect",
                        "evidence_sources": ["ss -tulpn", "/etc/ssh/sshd_config"],
                    },
                }
            ],
            "domains": [
                {
                    "score": 0.77,
                    "record": {
                        "domain": "host",
                        "description": "Host service exposure and credential posture",
                    },
                }
            ],
            "corpus": [
                {
                    "score": 0.55,
                    "record": {
                        "source_kind": "help",
                        "source_ref": "rg",
                        "title": "rg --help",
                        "text": "ripgrep usage and flags",
                    },
                },
                {
                    "score": 0.30,
                    "record": {
                        "source_kind": "code",
                        "source_ref": "src/main.py",
                        "title": "main runtime",
                        "text": "python orchestration logic",
                    },
                },
            ],
        }


class _FakeBackend:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def available(self):
        return True

    def generate(self, prompt: str, model: str | None = None, num_predict: int = 0):
        self.calls.append(
            {"prompt": prompt, "model": model, "num_predict": num_predict}
        )
        if self._responses:
            return self._responses.pop(0)
        return ""

    def list_models(self):
        return []


class PromptRouterTests(unittest.TestCase):
    def test_router_prefers_code_for_code_signals(self):
        router = PromptRouter()
        decision = router.decide("write a python function to parse json")
        self.assertEqual(decision.tier, "code")

    def test_router_prefers_deep_for_architecture_signal(self):
        router = PromptRouter()
        decision = router.decide("compare architecture tradeoffs for layered rag routing")
        self.assertEqual(decision.tier, "deep")

    def test_router_honors_explicit_preference(self):
        router = PromptRouter()
        decision = router.decide("hello", prefer="deep")
        self.assertEqual(decision.tier, "deep")
        self.assertEqual(decision.reason, "explicit_preference")


class LayeredAssistantTests(unittest.TestCase):
    def test_ask_routes_code_to_code_model_and_uses_context(self):
        backend = _FakeBackend(["print('ok')"])
        config = OrchestratorConfig(
            fast_model="fast-model",
            code_model="code-model",
            deep_model="deep-model",
        )
        assistant = LayeredAssistant(_FakeEngine(), backend=backend, config=config)

        result = assistant.ask("write python code to print hello")

        self.assertEqual(result["route"], "code")
        self.assertEqual(result["model_used"], "code-model")
        self.assertFalse(result["fallback_used"])
        self.assertEqual(result["context_counts"]["wickets"], 1)
        self.assertIn("ssh_open", backend.calls[0]["prompt"])

    def test_ask_falls_back_to_fast_when_first_model_is_empty(self):
        backend = _FakeBackend(["", "fallback answer"])
        config = OrchestratorConfig(
            fast_model="fast-model",
            code_model="code-model",
            deep_model="deep-model",
        )
        assistant = LayeredAssistant(_FakeEngine(), backend=backend, config=config)

        result = assistant.ask("analyze architecture for model orchestration")

        self.assertEqual(result["route"], "deep")
        self.assertEqual(result["model_used"], "fast-model")
        self.assertTrue(result["fallback_used"])
        self.assertEqual(result["models_attempted"], ["deep-model", "fast-model"])
        self.assertEqual(result["response"], "fallback answer")

    def test_candidate_plan_uses_configured_fallbacks(self):
        backend = _FakeBackend(["ok"])
        config = OrchestratorConfig(
            fast_model="fast-main",
            code_model="code-main",
            deep_model="deep-main",
            fast_fallback_models=("fast-alt",),
            code_fallback_models=("code-alt",),
            deep_fallback_models=("deep-alt",),
        )
        assistant = LayeredAssistant(_FakeEngine(), backend=backend, config=config)

        plan = assistant._candidate_plan("deep")
        self.assertEqual(plan, [("deep-main", 512), ("deep-alt", 512), ("fast-main", 192), ("fast-alt", 192)])

    def test_theta_code_prioritizes_code_corpus(self):
        backend = _FakeBackend(["ok"])
        config = OrchestratorConfig(
            fast_model="fast-model",
            code_model="code-model",
            deep_model="deep-model",
            max_context_lines=32,
        )
        assistant = LayeredAssistant(_FakeEngine(), backend=backend, config=config)

        result = assistant.ask("where is runtime code", prefer="fast", theta="code")
        corpus_lines = [line for line in result["context_preview"] if line.startswith("[code ") or line.startswith("[help ")]
        self.assertGreaterEqual(len(corpus_lines), 2)
        self.assertTrue(corpus_lines[0].startswith("[code "))

    def test_query_command_signal_prioritizes_help_line(self):
        class _CommandHeavyEngine:
            def surface(self, query: str, k_each: int = 3):
                return {
                    "query": query,
                    "wickets": [],
                    "adapters": [],
                    "domains": [],
                    "corpus": [
                        {
                            "score": 0.82,
                            "record": {
                                "source_kind": "code",
                                "source_ref": "skg/resonance/orchestrator.py",
                                "title": "orchestrator",
                                "text": "routing and prompt assembly",
                            },
                        },
                        {
                            "score": 0.20,
                            "record": {
                                "source_kind": "help",
                                "source_ref": "rg",
                                "title": "rg --help",
                                "text": "ripgrep usage and flags",
                            },
                        },
                    ],
                }

        backend = _FakeBackend(["ok"])
        config = OrchestratorConfig(
            fast_model="fast-model",
            code_model="code-model",
            deep_model="deep-model",
            max_context_lines=8,
        )
        assistant = LayeredAssistant(_CommandHeavyEngine(), backend=backend, config=config)
        result = assistant.ask("show rg help flags", prefer="fast", theta="runtime")
        self.assertTrue(result["context_preview"][0].startswith("[help "))


if __name__ == "__main__":
    unittest.main()
