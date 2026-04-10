import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skg.resonance.sphere_gpu import SphereGPU, SphereGPUConfig, SpherePoint


class _FakeAssistant:
    def __init__(self):
        self.calls = 0

    def ask(self, query: str, prefer=None, k_each=None, theta=None):
        self.calls += 1
        return {
            "query": query,
            "route": prefer or "fast",
            "route_reason": "fake",
            "model_used": f"{prefer or 'fast'}-model",
            "models_attempted": [f"{prefer or 'fast'}-model"],
            "num_predict": 64,
            "fallback_used": False,
            "latency_s": 0.01,
            "context_counts": {"wickets": 0, "adapters": 0, "domains": 0, "corpus": 0},
            "context_preview": [],
            "theta": theta or "",
            "response": f"ok:{prefer}:{k_each}:{theta}",
        }


class SphereGPUTests(unittest.TestCase):
    def test_inner_shell_defaults_to_fast(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        result = gpu.infer("hello", point=SpherePoint.from_values(r=0.1, theta="general", phi=0.2))
        self.assertEqual(result["sphere"]["shell"], "inner")
        self.assertEqual(result["sphere"]["prefer"], "fast")
        self.assertFalse(result["cache_hit"])

    def test_outer_shell_routes_to_deep(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        result = gpu.infer("analyze architecture", point=SpherePoint.from_values(r=0.9, theta="general", phi=0.5))
        self.assertEqual(result["sphere"]["shell"], "outer")
        self.assertEqual(result["sphere"]["prefer"], "deep")

    def test_theta_code_routes_to_code(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        result = gpu.infer("write a function", point=SpherePoint.from_values(r=0.2, theta="code", phi=0.3))
        self.assertEqual(result["sphere"]["prefer"], "code")

    def test_phi_escalates_tier(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                uncertainty_escalation_phi=0.7,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        result = gpu.infer("quick summary", point=SpherePoint.from_values(r=0.1, theta="general", phi=0.95))
        self.assertEqual(result["sphere"]["prefer"], "code")

    def test_cache_hit_on_repeat_query(self):
        assistant = _FakeAssistant()
        gpu = SphereGPU(
            assistant=assistant,
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                cache_size=16,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        point = SpherePoint.from_values(r=0.2, theta="general", phi=0.3)
        first = gpu.infer("same question", point=point)
        second = gpu.infer("same question", point=point)
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["cache_hit"])
        self.assertLessEqual(second["latency_s"], 0.01)
        self.assertEqual(assistant.calls, 1)

    def test_batch_preserves_order(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=4,
                shell_inner_max=2,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        requests = [
            {"query": "q1", "point": SpherePoint.from_values(r=0.1, theta="general", phi=0.2)},
            {"query": "q2", "point": SpherePoint.from_values(r=0.9, theta="general", phi=0.2)},
            {"query": "q3", "point": SpherePoint.from_values(r=0.2, theta="code", phi=0.2)},
        ]
        results = gpu.infer_batch(requests, max_workers=3)
        self.assertEqual([r["query"] for r in results], ["q1", "q2", "q3"])

    def test_state_persists_across_instances(self):
        with TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "sphere_state.json"
            cfg = SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                cache_size=16,
                persist_state=True,
                state_path=str(state_path),
                enable_resource_guard=False,
            )

            first_assistant = _FakeAssistant()
            gpu1 = SphereGPU(assistant=first_assistant, config=cfg)
            point = SpherePoint.from_values(r=0.2, theta="general", phi=0.3)
            first = gpu1.infer("persist me", point=point)
            self.assertFalse(first["cache_hit"])
            self.assertEqual(first_assistant.calls, 1)
            self.assertTrue(state_path.exists())

            second_assistant = _FakeAssistant()
            gpu2 = SphereGPU(assistant=second_assistant, config=cfg)
            second = gpu2.infer("persist me", point=point)
            self.assertTrue(second["cache_hit"])
            self.assertEqual(second_assistant.calls, 0)
            status = gpu2.status()
            self.assertGreaterEqual(status["stats"]["requests_total"], 2)

    def test_resource_guard_downgrades_on_hard_pressure(self):
        assistant = _FakeAssistant()
        gpu = SphereGPU(
            assistant=assistant,
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=True,
                persist_state=False,
            ),
        )
        gpu._resource_snapshot = lambda: {
            "load_ratio": 2.2,
            "mem_available_ratio": 0.06,
            "swap_used_ratio": 0.7,
        }
        result = gpu.infer("deep task", point=SpherePoint.from_values(r=0.9, theta="reason", phi=0.4))
        self.assertEqual(result["sphere"]["prefer"], "fast")
        self.assertIn("guard_hard", result["sphere"]["route_reason"])

    def test_infer_reports_auto_local_index_status(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=False,
                persist_state=False,
            ),
        )
        gpu._maybe_trigger_auto_local_index = lambda query, theta=None, force=False: {
            "started": False,
            "reason": "disabled",
        }
        result = gpu.infer("hello", point=SpherePoint.from_values(r=0.1, theta="general", phi=0.2))
        auto = result.get("sphere", {}).get("auto_local_index", {})
        self.assertEqual(auto.get("reason"), "disabled")

    def test_infer_reports_micro_local_index_status(self):
        gpu = SphereGPU(
            assistant=_FakeAssistant(),
            config=SphereGPUConfig(
                virtual_cores=2,
                shell_inner_max=1,
                shell_mid_max=1,
                shell_outer_max=1,
                enable_resource_guard=False,
                persist_state=False,
                enable_micro_local_corpus=False,
            ),
        )
        result = gpu.infer("hello", point=SpherePoint.from_values(r=0.1, theta="general", phi=0.2))
        micro = result.get("sphere", {}).get("micro_local_index", {})
        self.assertEqual(micro.get("reason"), "disabled")


if __name__ == "__main__":
    unittest.main()
