import json
import importlib.util
import os
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, "/opt/skg")

from skg.intel.surface import _read_interp_dir, surface
from skg.forge import proposals as forge_proposals
from skg.graph import WorkloadGraph, WicketPrior
from skg.kernel.engine import KernelStateEngine
from skg.kernel.field_functional import field_functional_breakdown, phi_fiber_breakdown
from skg.kernel.field_local import FieldLocal
from skg.kernel.folds import FoldDetector
from skg.kernel.energy import EnergyEngine
from skg.kernel.observations import Observation
from skg.kernel.pearl_manifold import PearlManifold
from skg.kernel.pearls import Pearl, PearlLedger
from skg.kernel.support import SupportContribution, SupportEngine
from skg.resonance.observation_memory import ObservationMemory
from skg.sensors import adapter_runner
from skg.sensors import envelope, precondition_payload
from skg.sensors.projector import project_event_file
from skg.substrate.projection import classify, load_states_from_events, load_states_from_events_priority
from skg.topology.energy import (
    Fiber,
    FiberCluster,
    SphereEnergy,
    WicketState,
    _sphere_for_wicket,
    _world_states_from_surface,
    _world_states_from_snapshot,
    _world_snapshot_fibers,
    compute_sphere_energy,
    compute_field_fibers,
    decompose_field_topology,
    fiber_coupling_matrix,
    fiber_tension_by_sphere,
    merge_coupling_matrices,
)


def _load_gravity_field_module():
    spec = importlib.util.spec_from_file_location(
        "skg_gravity_field_test",
        "/opt/skg/skg-gravity/gravity_field.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_daemon_module():
    class _DummyApp:
        def get(self, *args, **kwargs):
            return lambda fn: fn

        def post(self, *args, **kwargs):
            return lambda fn: fn

        def mount(self, *args, **kwargs):
            return None

    class _DummyHTTPException(Exception):
        pass

    class _DummyStaticFiles:
        def __init__(self, *args, **kwargs):
            pass

    class _DummyBaseModel:
        pass

    sys.modules.setdefault("uvicorn", types.SimpleNamespace(run=lambda *a, **k: None))
    sys.modules.setdefault("fastapi", types.SimpleNamespace(FastAPI=lambda *a, **k: _DummyApp(), HTTPException=_DummyHTTPException))
    sys.modules.setdefault("fastapi.responses", types.SimpleNamespace(FileResponse=object, RedirectResponse=object))
    sys.modules.setdefault("fastapi.staticfiles", types.SimpleNamespace(StaticFiles=_DummyStaticFiles))
    sys.modules.setdefault("pydantic", types.SimpleNamespace(BaseModel=_DummyBaseModel))
    spec = importlib.util.spec_from_file_location(
        "skg_daemon_test",
        "/opt/skg/skg/core/daemon.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_exploit_dispatch_module():
    spec = importlib.util.spec_from_file_location(
        "skg_exploit_dispatch_test",
        "/opt/skg/skg-gravity/exploit_dispatch.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_cred_reuse_module():
    spec = importlib.util.spec_from_file_location(
        "skg_cred_reuse_test",
        "/opt/skg/skg-gravity/cred_reuse.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SensorProjectionLoopTests(unittest.TestCase):
    def test_canonical_field_functional_is_order_stable_and_curved(self):
        web_local = FieldLocal(
            local_id="10.0.0.7::web",
            workload_id="10.0.0.7",
            domain="web",
            wicket_states={
                "WB-01": SupportContribution(
                    unresolved=0.6,
                    contradiction=0.1,
                    decoherence=0.05,
                    compatibility_score=0.5,
                    compatibility_span=1,
                )
            },
        )
        data_local = FieldLocal(
            local_id="10.0.0.7::data",
            workload_id="10.0.0.7",
            domain="data",
            wicket_states={
                "DA-01": SupportContribution(
                    unresolved=0.4,
                    contradiction=0.0,
                    decoherence=0.08,
                    compatibility_score=0.7,
                    compatibility_span=2,
                )
            },
        )
        cluster = FiberCluster(
            cluster_id="cluster::10.0.0.7",
            anchor="10.0.0.7",
            spheres=["web", "data"],
            kinds=["access_path", "datastore"],
            member_count=4,
            total_coherence=1.7,
            total_tension=1.1,
            fibers=[
                Fiber(
                    fiber_id="f-web",
                    sphere="web",
                    kind="access_path",
                    anchor="10.0.0.7",
                    members=["credential-a", "service-http"],
                    coherence=0.9,
                    tension=0.7,
                ),
                Fiber(
                    fiber_id="f-data",
                    sphere="data",
                    kind="datastore",
                    anchor="10.0.0.7",
                    members=["credential-a", "service-mysql"],
                    coherence=0.8,
                    tension=0.4,
                ),
            ],
        )
        topology = decompose_field_topology(
            sphere_energies={
                "web": SphereEnergy(
                    sphere="web",
                    G=0.2,
                    G_norm=0.3,
                    n_wickets=3,
                    n_realized=1,
                    n_blocked=0,
                    n_unknown=2,
                    unknown_mass=2.0,
                    total_local_energy=0.7,
                    mean_local_energy=0.35,
                    n_latent=0,
                ),
                "data": SphereEnergy(
                    sphere="data",
                    G=0.4,
                    G_norm=0.45,
                    n_wickets=2,
                    n_realized=0,
                    n_blocked=0,
                    n_unknown=2,
                    unknown_mass=1.3,
                    total_local_energy=0.6,
                    mean_local_energy=0.3,
                    n_latent=0,
                ),
            },
            coupling={"web": {"data": 0.7}, "data": {"web": 0.7}},
            fiber_tension={"web": 0.3, "data": 0.2},
            pearl_persistence={"web": 0.0, "data": 0.0},
            beta_1=1,
            h1_obstruction_count=1,
        )

        ab = field_functional_breakdown([web_local, data_local], fiber_cluster=cluster, topology=topology)
        ba = field_functional_breakdown([data_local, web_local], fiber_cluster=cluster, topology=topology)

        self.assertAlmostEqual(ab.self_energy, ba.self_energy, places=6)
        self.assertAlmostEqual(ab.coupling_energy, ba.coupling_energy, places=6)
        self.assertAlmostEqual(ab.total, ba.total, places=6)
        self.assertGreater(ab.curvature, 0.0)
        self.assertIn("web", ab.relevant_spheres)
        self.assertIn("data", ab.relevant_spheres)

    def test_fiber_breakdown_uses_actual_cluster_structure(self):
        host_local = FieldLocal(
            local_id="10.0.0.7::host",
            workload_id="10.0.0.7",
            domain="host",
            wicket_states={
                "HO-01": SupportContribution(
                    unresolved=0.2,
                    contradiction=0.0,
                    decoherence=0.0,
                    compatibility_score=0.1,
                    compatibility_span=1,
                )
            },
        )
        data_local = FieldLocal(
            local_id="10.0.0.7::data",
            workload_id="10.0.0.7",
            domain="data",
            wicket_states={
                "DA-01": SupportContribution(
                    unresolved=0.9,
                    contradiction=0.0,
                    decoherence=0.1,
                    compatibility_score=0.2,
                    compatibility_span=1,
                )
            },
        )
        cluster = FiberCluster(
            cluster_id="cluster::10.0.0.7",
            anchor="10.0.0.7",
            spheres=["host", "data"],
            kinds=["credential_binding", "datastore"],
            member_count=4,
            total_coherence=1.85,
            total_tension=2.2,
            fibers=[
                Fiber(
                    fiber_id="f-host",
                    sphere="host",
                    kind="credential_binding",
                    anchor="10.0.0.7",
                    members=["cred-a", "shared-token"],
                    coherence=0.95,
                    tension=1.4,
                ),
                Fiber(
                    fiber_id="f-data",
                    sphere="data",
                    kind="datastore",
                    anchor="10.0.0.7",
                    members=["shared-token", "mysql"],
                    coherence=0.9,
                    tension=0.8,
                ),
            ],
        )

        base = phi_fiber_breakdown(["HO-01"], 1.0, [host_local, data_local])
        enriched = phi_fiber_breakdown(["HO-01"], 1.0, [host_local, data_local], fiber_cluster=cluster)

        self.assertGreater(enriched.tension, base.tension)
        self.assertNotEqual(enriched.coupling, base.coupling)
        self.assertEqual(enriched.coupling, 0.0)
        self.assertGreater(base.coupling, 0.0)
        self.assertEqual(enriched.fiber_cluster_id, "cluster::10.0.0.7")
        self.assertGreater(enriched.total, base.total)

    def test_kernel_instrument_potential_uses_fiber_cluster_context(self):
        kernel = KernelStateEngine(Path("/tmp/skg_discovery"), Path("/tmp/skg_state/events"))
        states = {
            "HO-01": {
                "status": "unknown",
                "phi_u": 0.3,
                "contradiction": 0.0,
                "decoherence": 0.0,
                "compatibility_score": 0.1,
                "compatibility_span": 1,
            },
            "DA-01": {
                "status": "unknown",
                "phi_u": 0.9,
                "contradiction": 0.0,
                "decoherence": 0.1,
                "compatibility_score": 0.2,
                "compatibility_span": 1,
            },
        }
        cluster = FiberCluster(
            cluster_id="cluster::10.0.0.7",
            anchor="10.0.0.7",
            spheres=["host", "data"],
            kinds=["credential_binding", "datastore"],
            member_count=4,
            total_coherence=1.85,
            total_tension=2.2,
            fibers=[
                Fiber(
                    fiber_id="f-host",
                    sphere="host",
                    kind="credential_binding",
                    anchor="10.0.0.7",
                    members=["cred-a", "shared-token"],
                    coherence=0.95,
                    tension=1.4,
                ),
                Fiber(
                    fiber_id="f-data",
                    sphere="data",
                    kind="datastore",
                    anchor="10.0.0.7",
                    members=["shared-token", "mysql"],
                    coherence=0.9,
                    tension=0.8,
                ),
            ],
        )

        kwargs = {
            "instrument_name": "nmap",
            "instrument_wavelength": ["HO-01"],
            "instrument_cost": 1.0,
            "node_key": "10.0.0.7",
            "applicable_wickets": {"HO-01", "DA-01"},
            "domain_wickets": {"host": {"HO-01"}, "data": {"DA-01"}},
        }

        with mock.patch.object(kernel, "states_with_detail", return_value=states):
            with mock.patch.object(kernel, "_fiber_clusters_by_anchor", return_value={}):
                baseline = kernel.instrument_potential(**kwargs)
            with mock.patch.object(kernel, "_fiber_clusters_by_anchor", return_value={"10.0.0.7": cluster}):
                enriched = kernel.instrument_potential(**kwargs)

        self.assertGreater(enriched, baseline)

    def test_substrate_classify_collapses_on_blocked_even_with_unknowns(self):
        self.assertEqual(
            classify(
                realized=["CE-01"],
                blocked=["CE-02"],
                unknown=["CE-09", "CE-10", "CE-14"],
                required=["CE-01", "CE-02", "CE-09", "CE-10", "CE-14"],
            ),
            "not_realized",
        )

    def test_precondition_payload_keeps_status_and_aliases_toolchain(self):
        payload = precondition_payload(
            wicket_id="HO-01",
            domain="host",
            workload_id="host::10.0.0.7",
            realized=True,
        )
        self.assertEqual(payload["status"], "realized")
        self.assertTrue(payload["realized"])
        self.assertEqual(payload["node_id"], "HO-01")
        self.assertEqual(payload["identity_key"], "10.0.0.7")
        self.assertEqual(payload["manifestation_key"], "host::10.0.0.7")
        self.assertEqual(payload["target_ip"], "10.0.0.7")

        event = envelope(
            event_type="obs.attack.precondition",
            source_id="test/host",
            toolchain="host",
            payload=payload,
            evidence_rank=1,
            source_kind="test",
            pointer="test://host",
        )
        self.assertEqual(event["source"]["toolchain"], "skg-host-toolchain")

    def test_project_event_file_accepts_adapter_style_events(self):
        events = []
        for wicket_id in ("HO-01", "HO-02", "HO-03"):
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id=f"test/{wicket_id}",
                toolchain="host",
                payload=precondition_payload(
                    wicket_id=wicket_id,
                    domain="host",
                    workload_id="host-a",
                    attack_path_id="host_ssh_initial_access_v1",
                    realized=True,
                ),
                evidence_rank=1,
                source_kind="test",
                pointer=f"test://{wicket_id}",
            ))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            events_file = tmp / "events.ndjson"
            interp_dir = tmp / "interp"
            with events_file.open("w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps(event) + "\n")

            outputs = project_event_file(events_file, interp_dir, run_id="run-1")
            self.assertEqual(len(outputs), 1)

            result = json.loads(outputs[0].read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "realized")
            self.assertEqual(result["attack_path_id"], "host_ssh_initial_access_v1")
            self.assertEqual(sorted(result["realized"]), ["HO-01", "HO-02", "HO-03"])

    def test_host_projection_uses_support_instead_of_latest_unknown(self):
        events = [
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/HO-01",
                toolchain="host",
                payload=precondition_payload(
                    wicket_id="HO-01",
                    domain="host",
                    workload_id="host-a",
                    attack_path_id="host_ssh_initial_access_v1",
                    realized=True,
                ),
                evidence_rank=1,
                source_kind="test",
                pointer="test://HO-01",
            ),
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/HO-02",
                toolchain="host",
                payload=precondition_payload(
                    wicket_id="HO-02",
                    domain="host",
                    workload_id="host-a",
                    attack_path_id="host_ssh_initial_access_v1",
                    realized=True,
                ),
                evidence_rank=1,
                source_kind="test",
                pointer="test://HO-02",
            ),
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/HO-03-R",
                toolchain="host",
                payload=precondition_payload(
                    wicket_id="HO-03",
                    domain="host",
                    workload_id="host-a",
                    attack_path_id="host_ssh_initial_access_v1",
                    realized=True,
                ),
                evidence_rank=1,
                source_kind="test",
                pointer="test://HO-03-realized",
            ),
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/HO-03-U",
                toolchain="host",
                payload={
                    **precondition_payload(
                        wicket_id="HO-03",
                        domain="host",
                        workload_id="host-a",
                        attack_path_id="host_ssh_initial_access_v1",
                        realized=False,
                    ),
                    "status": "unknown",
                    "realized": False,
                    "blocked": False,
                },
                evidence_rank=1,
                source_kind="test",
                pointer="test://HO-03-unknown",
            ),
        ]
        for idx in (0, 1, 2):
            events[idx]["ts"] = "2026-03-16T00:00:00+00:00"
            events[idx]["payload"]["observed_at"] = "2026-03-16T00:00:00+00:00"
        events[-1]["ts"] = "2026-03-16T00:00:01+00:00"
        events[-1]["payload"]["observed_at"] = "2026-03-16T00:00:01+00:00"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            events_file = tmp / "events.ndjson"
            interp_dir = tmp / "interp"
            with events_file.open("w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps(event) + "\n")

            outputs = project_event_file(events_file, interp_dir, run_id="run-1")
            self.assertEqual(len(outputs), 1)

            result = json.loads(outputs[0].read_text(encoding="utf-8"))
            self.assertEqual(result["attack_path_id"], "host_ssh_initial_access_v1")
            self.assertEqual(result["classification"], "realized")
            self.assertEqual(sorted(result["realized"]), ["HO-01", "HO-02", "HO-03"])

    def test_substrate_state_loader_preserves_support_and_why(self):
        events = [
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/HO-03-R",
                toolchain="host",
                payload=precondition_payload(
                    wicket_id="HO-03",
                    domain="host",
                    workload_id="host::172.17.0.3",
                    attack_path_id="host_ssh_initial_access_v1",
                    realized=True,
                    detail="credential valid via ssh key",
                ),
                evidence_rank=1,
                source_kind="ssh_auth",
                pointer="ssh://172.17.0.3:22",
            ),
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/HO-03-U",
                toolchain="host",
                payload={
                    **precondition_payload(
                        wicket_id="HO-03",
                        domain="host",
                        workload_id="host::172.17.0.3",
                        attack_path_id="host_ssh_initial_access_v1",
                        realized=False,
                    ),
                    "status": "unknown",
                    "realized": False,
                    "blocked": False,
                    "detail": "later probe inconclusive",
                },
                evidence_rank=1,
                source_kind="ssh_auth",
                pointer="ssh://172.17.0.3:22?retry=1",
            ),
        ]
        events[0]["ts"] = "2026-03-16T00:00:00+00:00"
        events[0]["payload"]["observed_at"] = "2026-03-16T00:00:00+00:00"
        events[-1]["ts"] = "2026-03-16T00:00:01+00:00"
        events[-1]["payload"]["observed_at"] = "2026-03-16T00:00:01+00:00"

        states = load_states_from_events(events)
        self.assertIn("HO-03", states)
        node = states["HO-03"]
        self.assertEqual(node.state.value, "realized")
        self.assertEqual(node.source_kind, "ssh_auth")
        self.assertEqual(node.pointer, "ssh://172.17.0.3:22")
        self.assertEqual(node.notes, "credential valid via ssh key")
        self.assertGreater(node.attributes["phi_r"], 0.5)
        self.assertEqual(node.attributes["phi_b"], 0.0)
        self.assertEqual(node.attributes["support_basis"], "aggregated_observation_support")

    def test_substrate_unknown_carries_unresolved_reason(self):
        events = [
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/WB-09-U",
                toolchain="web",
                payload={
                    **precondition_payload(
                        wicket_id="WB-09",
                        domain="web",
                        workload_id="web::172.17.0.3",
                        attack_path_id="web_sqli_to_shell_v1",
                        realized=False,
                    ),
                    "status": "unknown",
                    "realized": False,
                    "blocked": False,
                    "detail": "page reachable but injection surface still inconclusive",
                },
                evidence_rank=1,
                source_kind="http_probe",
                pointer="http://172.17.0.3/",
            ),
        ]

        states = load_states_from_events(events)
        node = states["WB-09"]
        self.assertEqual(node.state.value, "unknown")
        self.assertEqual(node.attributes["unresolved_reason"], "single_basis")
        self.assertGreater(node.attributes["phi_u"], 0.0)
        self.assertGreaterEqual(node.local_energy, node.attributes["phi_u"])

    def test_priority_state_loader_preserves_blocked_dominance_with_why(self):
        events = [
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/CE-02-R",
                toolchain="container_escape",
                payload=precondition_payload(
                    wicket_id="CE-02",
                    domain="container_escape",
                    workload_id="ce::172.17.0.3",
                    attack_path_id="container_escape_privileged_v1",
                    realized=True,
                    detail="container appears privileged from one probe",
                ),
                evidence_rank=1,
                source_kind="container_probe",
                pointer="docker://inspect/guess",
            ),
            envelope(
                event_type="obs.attack.precondition",
                source_id="test/CE-02-B",
                toolchain="container_escape",
                payload={
                    **precondition_payload(
                        wicket_id="CE-02",
                        domain="container_escape",
                        workload_id="ce::172.17.0.3",
                        attack_path_id="container_escape_privileged_v1",
                        realized=False,
                    ),
                    "status": "blocked",
                    "realized": False,
                    "blocked": True,
                    "detail": "docker inspect confirms privileged=false",
                },
                evidence_rank=1,
                source_kind="container_probe",
                pointer="docker://inspect/ce-02",
            ),
        ]
        events[0]["ts"] = "2026-03-16T00:00:00+00:00"
        events[0]["payload"]["observed_at"] = "2026-03-16T00:00:00+00:00"
        events[-1]["ts"] = "2026-03-16T00:00:01+00:00"
        events[-1]["payload"]["observed_at"] = "2026-03-16T00:00:01+00:00"

        states = load_states_from_events_priority(events, required=["CE-02"])
        self.assertIn("CE-02", states)
        node = states["CE-02"]
        self.assertEqual(node.state.value, "blocked")
        self.assertEqual(node.source_kind, "container_probe")
        self.assertEqual(node.pointer, "docker://inspect/ce-02")
        self.assertEqual(node.notes, "docker inspect confirms privileged=false")
        self.assertGreater(node.attributes["phi_b"], 0.0)
        self.assertEqual(node.attributes["support_basis"], "priority_support_aggregation")

    def test_surface_reads_wrapped_interp_payloads(self):
        wrapped = {
            "id": "interp-1",
            "type": "interp.host.realizability",
            "payload": {
                "workload_id": "host-a",
                "attack_path_id": "host_ssh_initial_access_v1",
                "classification": "realized",
                "host_score": 1.0,
                "realized": ["HO-01", "HO-02", "HO-03"],
                "blocked": [],
                "unknown": [],
                "computed_at": "2026-03-15T00:00:00+00:00",
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            interp_dir = Path(tmpdir)
            (interp_dir / "host_host-a_run-1.json").write_text(
                json.dumps(wrapped),
                encoding="utf-8",
            )
            rows = _read_interp_dir(interp_dir)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["attack_path_id"], "host_ssh_initial_access_v1")
        self.assertEqual(rows[0]["classification"], "realized")

    def test_surface_exposes_identity_key_separately_from_workload_id(self):
        payloads = [
            (
                "host_host__172.17.0.3_run-1.json",
                {
                    "payload": {
                        "workload_id": "host::172.17.0.3",
                        "attack_path_id": "host_ssh_initial_access_v1",
                        "classification": "realized",
                        "host_score": 1.0,
                        "realized": ["HO-01", "HO-02", "HO-03"],
                        "blocked": [],
                        "unknown": [],
                        "computed_at": "2026-03-17T00:00:00+00:00",
                    }
                },
            ),
            (
                "ssh_ssh__172.17.0.3_run-1.json",
                {
                    "payload": {
                        "workload_id": "ssh::172.17.0.3",
                        "attack_path_id": "host_linux_privesc_sudo_v1",
                        "classification": "indeterminate",
                        "host_score": 0.5,
                        "realized": ["HO-03"],
                        "blocked": [],
                        "unknown": ["HO-06"],
                        "computed_at": "2026-03-17T00:00:01+00:00",
                    }
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            interp_dir = Path(tmpdir)
            for filename, payload in payloads:
                (interp_dir / filename).write_text(json.dumps(payload), encoding="utf-8")
            surf = surface(interp_dir)

        by_workload = {row["workload_id"]: row for row in surf["workloads"]}
        self.assertEqual(by_workload["host::172.17.0.3"]["identity_key"], "172.17.0.3")
        self.assertEqual(by_workload["ssh::172.17.0.3"]["identity_key"], "172.17.0.3")
        self.assertEqual(by_workload["host::172.17.0.3"]["manifestation_key"], "host::172.17.0.3")
        self.assertEqual(by_workload["ssh::172.17.0.3"]["manifestation_key"], "ssh::172.17.0.3")

    def test_graph_prior_falls_back_to_shared_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            graph = WorkloadGraph(Path(tmpdir))
            graph._priors["ssh::172.17.0.3::HO-03"] = WicketPrior(
                workload_id="ssh::172.17.0.3",
                wicket_id="HO-03",
                domain="host",
                prior=0.6,
                sources=["seed"],
                last_updated="2026-03-17T00:00:00+00:00",
                projection_count=0,
            )
            self.assertEqual(graph.get_prior("host::172.17.0.3", wicket_id="HO-03"), 0.6)

    def test_graph_neighbors_include_same_identity_virtual_bond(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            graph = WorkloadGraph(Path(tmpdir))
            graph._priors["host::172.17.0.3::HO-03"] = WicketPrior(
                workload_id="host::172.17.0.3",
                wicket_id="HO-03",
                domain="host",
                prior=0.4,
                sources=["seed"],
                last_updated="2026-03-17T00:00:00+00:00",
                projection_count=0,
            )
            graph._priors["web::172.17.0.3::WB-01"] = WicketPrior(
                workload_id="web::172.17.0.3",
                wicket_id="WB-01",
                domain="web",
                prior=0.3,
                sources=["seed"],
                last_updated="2026-03-17T00:00:00+00:00",
                projection_count=0,
            )

            neighbors = graph.neighbors("host::172.17.0.3")

        self.assertIn(("web::172.17.0.3", "same_identity", 0.85), neighbors)

    def test_surface_reader_prefers_newest_projection_by_mtime(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            interp_dir = Path(tmpdir)
            older = interp_dir / "host_demo_zzzz9999.json"
            newer = interp_dir / "host_demo_aaaa0001.json"

            older.write_text(json.dumps({
                "workload_id": "host::10.0.0.1",
                "attack_path_id": "host_ssh_initial_access_v1",
                "classification": "realized",
                "host_score": 1.0,
            }))
            newer.write_text(json.dumps({
                "workload_id": "host::10.0.0.1",
                "attack_path_id": "host_ssh_initial_access_v1",
                "classification": "not_realized",
                "host_score": 0.0,
            }))
            os.utime(older, (older.stat().st_atime, older.stat().st_mtime - 5))

            rows = _read_interp_dir(interp_dir)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["classification"], "not_realized")

    def test_surface_includes_graph_neighbors_above_min_weight(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            interp_dir = base / "interp"
            graph_dir = base / "graph"
            interp_dir.mkdir()

            (interp_dir / "host_demo.json").write_text(json.dumps({
                "workload_id": "host::10.0.0.1",
                "attack_path_id": "host_ssh_initial_access_v1",
                "classification": "indeterminate",
                "required_wickets": ["HO-01"],
                "realized": [],
                "blocked": [],
                "unknown": ["HO-01"],
                "host_score": 0.0,
            }))

            graph = WorkloadGraph(graph_dir)
            graph.add_edge("host::10.0.0.1", "web::10.0.0.2", "same_subnet")

            result = surface(interp_dir=interp_dir, graph=graph)

        self.assertEqual(result["workloads"][0]["neighbors"], ["web::10.0.0.2"])

    def test_weighted_energy_counts_unresolved_mass_not_only_flat_unknown(self):
        engine = EnergyEngine()
        flat = engine.compute_weighted(
            [{"status": "unknown"}],
            [],
        )
        conflicted = engine.compute_weighted(
            [{"status": "unknown", "phi_u": 0.6, "contradiction": 0.4, "local_energy": 1.0}],
            [],
        )
        self.assertEqual(flat, 1.0)
        self.assertGreater(conflicted, flat)

    def test_support_engine_tracks_compatibility_across_measurement_families(self):
        now = datetime(2026, 3, 19, 12, 0, 0, tzinfo=timezone.utc)
        engine = SupportEngine()
        obs = [
            Observation(
                instrument="nmap",
                targets=["172.17.0.3"],
                context="HO-03",
                payload={},
                event_time=now,
                support_mapping={"172.17.0.3": {"R": 0.8, "B": 0.0, "U": 0.0}},
            ),
            Observation(
                instrument="ssh_sensor",
                targets=["172.17.0.3"],
                context="HO-03",
                payload={},
                event_time=now,
                support_mapping={"172.17.0.3": {"R": 0.9, "B": 0.0, "U": 0.0}},
            ),
        ]
        contrib = engine.aggregate(obs, "172.17.0.3", "HO-03", now)
        self.assertEqual(contrib.compatibility_span, 2)
        self.assertGreater(contrib.compatibility_score, 0.0)

    def test_support_engine_tracks_decoherence_from_stale_single_basis_observation(self):
        now = datetime(2026, 3, 19, 12, 0, 0, tzinfo=timezone.utc)
        engine = SupportEngine()
        obs = [
            Observation(
                instrument="pcap",
                targets=["172.17.0.3"],
                context="WB-09",
                payload={},
                event_time=datetime(2026, 3, 19, 10, 0, 0, tzinfo=timezone.utc),
                decay_class="ephemeral",
                support_mapping={"172.17.0.3": {"R": 0.0, "B": 0.0, "U": 0.9}},
            ),
        ]
        contrib = engine.aggregate(obs, "172.17.0.3", "WB-09", now)
        self.assertGreater(contrib.decoherence, 0.0)
        self.assertEqual(contrib.compatibility_span, 1)

    def test_support_engine_expires_observations_past_ttl(self):
        now = datetime(2026, 3, 19, 12, 0, 0, tzinfo=timezone.utc)
        engine = SupportEngine()
        obs = [
            Observation(
                instrument="pcap",
                targets=["172.17.0.3"],
                context="WB-09",
                payload={},
                event_time=datetime(2026, 3, 18, 0, 0, 0, tzinfo=timezone.utc),
                decay_class="ephemeral",
                support_mapping={"172.17.0.3": {"R": 0.0, "B": 0.0, "U": 0.9}},
            ),
            Observation(
                instrument="ssh_sensor",
                targets=["172.17.0.3"],
                context="WB-09",
                payload={},
                event_time=datetime(2026, 3, 19, 11, 0, 0, tzinfo=timezone.utc),
                decay_class="operational",
                support_mapping={"172.17.0.3": {"R": 0.7, "B": 0.0, "U": 0.0}},
            ),
        ]
        self.assertTrue(engine.is_expired(obs[0], now))
        self.assertFalse(engine.is_expired(obs[1], now))
        contrib = engine.aggregate(obs, "172.17.0.3", "WB-09", now)
        self.assertGreater(contrib.realized, 0.68)
        self.assertLess(contrib.realized, 0.7)
        self.assertAlmostEqual(contrib.unresolved, 0.0, places=3)
        self.assertEqual(contrib.compatibility_span, 1)

    def test_observation_memory_recall_uses_shared_identity(self):
        class FakeEmbedder:
            dim = 4

            def embed(self, texts):
                return __import__("numpy").ones((len(texts), self.dim), dtype="float32")

            def embed_one(self, text):
                return __import__("numpy").ones((self.dim,), dtype="float32")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mem = ObservationMemory(root / "index", root / "records", FakeEmbedder())
            mem.load()
            for i in range(3):
                rid = mem.record_observation(
                    evidence_text=f"ssh auth success {i}",
                    wicket_id="HO-03",
                    domain="host",
                    source_kind="ssh_auth",
                    evidence_rank=1,
                    sensor_realized=True,
                    confidence_at_emit=0.95,
                    workload_id="ssh::172.17.0.3",
                    ts=f"2026-03-17T00:00:0{i}+00:00",
                )
                mem.record_outcome(rid, "realized")

            rate = mem.historical_confirmation_rate(
                evidence_text="host auth validation",
                wicket_id="HO-03",
                domain="host",
                workload_id="host::172.17.0.3",
                k=3,
            )
            self.assertEqual(rate, 1.0)

    def test_pearl_ledger_enriches_identity_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = PearlLedger(Path(tmpdir) / "pearls.jsonl")
            pearl = Pearl(
                energy_snapshot={"workload_id": "ssh::172.17.0.3", "target_ip": "172.17.0.3"},
                target_snapshot={},
            )
            ledger.record(pearl)
            loaded = ledger.all()[0]
            self.assertEqual(loaded.energy_snapshot["identity_key"], "172.17.0.3")
            self.assertEqual(loaded.energy_snapshot["manifestation_key"], "ssh::172.17.0.3")
            self.assertEqual(loaded.target_snapshot["identity_key"], "172.17.0.3")

    def test_temporal_folds_dedup_by_identity_across_manifestations(self):
        detector = FoldDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            events_dir = Path(tmpdir)
            events = [
                envelope(
                    event_type="obs.attack.precondition",
                    source_id="test/ssh",
                    toolchain="host",
                    payload=precondition_payload(
                        wicket_id="HO-03",
                        domain="host",
                        workload_id="ssh::172.17.0.3",
                        attack_path_id="host_ssh_initial_access_v1",
                        realized=True,
                    ),
                    evidence_rank=1,
                    source_kind="ssh_auth",
                    pointer="ssh://172.17.0.3:22",
                ),
                envelope(
                    event_type="obs.attack.precondition",
                    source_id="test/host",
                    toolchain="host",
                    payload=precondition_payload(
                        wicket_id="HO-03",
                        domain="host",
                        workload_id="host::172.17.0.3",
                        attack_path_id="host_ssh_initial_access_v1",
                        realized=True,
                    ),
                    evidence_rank=1,
                    source_kind="ssh_auth",
                    pointer="ssh://172.17.0.3:22?host",
                ),
            ]
            for ev in events:
                ev["ts"] = "2026-03-15T00:00:00+00:00"
                ev["payload"]["observed_at"] = "2026-03-15T00:00:00+00:00"
            (events_dir / "events.ndjson").write_text(
                "\n".join(json.dumps(ev) for ev in events) + "\n",
                encoding="utf-8",
            )

            folds = detector.detect_temporal(events_dir)

        matching = [f for f in folds if f.why.get("wicket_id") == "HO-03"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].location, "172.17.0.3")
        self.assertEqual(matching[0].why["identity_key"], "172.17.0.3")

    def test_temporal_folds_use_configured_state_dir_for_pearls(self):
        import skg.kernel.folds as folds_module

        detector = FoldDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir)
            pearl = {
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
                "energy_snapshot": {
                    "workload_id": "host::10.0.0.7",
                    "identity_key": "10.0.0.7",
                    "decay_class": "operational",
                },
                "state_changes": [
                    {"wicket_id": "HO-03", "to": "realized"},
                ],
            }
            (state_dir / "pearls.jsonl").write_text(
                json.dumps(pearl) + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(folds_module, "SKG_STATE_DIR", state_dir):
                folds = detector.detect_temporal(state_dir / "missing-events")

        matching = [f for f in folds if f.why.get("wicket_id") == "HO-03"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].why["identity_key"], "10.0.0.7")

    def test_pearl_manifold_groups_reinforced_wickets_by_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = PearlLedger(Path(tmpdir) / "pearls.jsonl")
            for wid in ("ssh::172.17.0.3", "host::172.17.0.3"):
                ledger.record(Pearl(
                    state_changes=[{"wicket_id": "HO-03", "to": "realized"}],
                    energy_snapshot={"workload_id": wid, "domain": "host", "E": 1.0},
                    target_snapshot={"domain": "host"},
                ))

            manifold = PearlManifold(ledger)
            neighborhoods = manifold.neighborhoods()

        self.assertEqual(len(neighborhoods), 1)
        self.assertEqual(neighborhoods[0].identity_key, "172.17.0.3")
        self.assertEqual(neighborhoods[0].domain, "host")
        self.assertEqual(neighborhoods[0].reinforced_wickets, ["HO-03"])

    def test_pearl_manifold_recall_adjustment_uses_identity_hosts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = PearlLedger(Path(tmpdir) / "pearls.jsonl")
            for wid in ("ssh::172.17.0.3", "host::172.17.0.3"):
                ledger.record(Pearl(
                    state_changes=[{"wicket_id": "HO-03", "to": "realized"}],
                    energy_snapshot={"workload_id": wid, "domain": "host", "E": 1.0},
                    target_snapshot={"domain": "host"},
                ))

            manifold = PearlManifold(ledger)
            adj = manifold.recall_adjustment(domain="host", hosts=["host::172.17.0.3"])

        self.assertGreater(adj["delta"], 0.0)
        self.assertEqual(adj["reinforced_wickets"], ["HO-03"])

    def test_pearl_manifold_wavelength_boost_uses_reinforced_wickets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = PearlLedger(Path(tmpdir) / "pearls.jsonl")
            for wid in ("ssh::172.17.0.3", "host::172.17.0.3"):
                ledger.record(Pearl(
                    state_changes=[{"wicket_id": "HO-03", "to": "realized"}],
                    energy_snapshot={"workload_id": wid, "domain": "host", "E": 1.0},
                    target_snapshot={"domain": "host"},
                ))

            manifold = PearlManifold(ledger)
            boost = manifold.wavelength_boost(
                hosts=["host::172.17.0.3"],
                wavelength=["HO-*"],
            )

        self.assertGreater(boost, 0.0)

    def test_pearl_manifold_can_reinforce_from_observation_confirms(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = PearlLedger(Path(tmpdir) / "pearls.jsonl")
            for wid in ("ssh::172.17.0.3", "host::172.17.0.3"):
                ledger.record(Pearl(
                    observation_confirms=[{"wicket_id": "HO-03", "status": "realized", "workload_id": wid}],
                    energy_snapshot={"workload_id": wid, "domain": "host", "E": 1.0},
                    target_snapshot={"domain": "host"},
                ))

            manifold = PearlManifold(ledger)
            neighborhoods = manifold.neighborhoods()

        self.assertEqual(len(neighborhoods), 1)
        self.assertEqual(neighborhoods[0].reinforced_wickets, ["HO-03"])

    def test_pearl_manifold_growth_adjustment_uses_proposal_lifecycle_memory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = PearlLedger(Path(tmpdir) / "pearls.jsonl")
            for reason in ("proposal_created", "proposal_created_backfill", "clustered_catalog_growth"):
                ledger.record(Pearl(
                    reason_changes=[{
                        "kind": "proposal_lifecycle",
                        "reason": reason,
                        "domain": "web",
                    }],
                    energy_snapshot={"workload_id": "growth::172.17.0.3", "domain": "web"},
                    target_snapshot={"domain": "web"},
                ))

            manifold = PearlManifold(ledger)
            adj = manifold.growth_adjustment(domain="web", hosts=["172.17.0.3"])

        self.assertGreater(adj["delta"], 0.0)
        self.assertIn("proposal_created", adj["proposal_reasons"])
        self.assertIn("clustered_catalog_growth", adj["proposal_reasons"])

    def test_proposal_recall_adjustment_matches_identity_hosts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir)
            records_dir = state_dir / "resonance" / "records"
            records_dir.mkdir(parents=True, exist_ok=True)
            (records_dir / "observations.jsonl").write_text(
                "\n".join([
                    json.dumps({
                        "workload_id": "mysql::db.internal:3306::users",
                        "domain": "data",
                        "projection_confirmed": "realized",
                        "evidence_text": "db.internal measurement",
                    }),
                    json.dumps({
                        "workload_id": "mysql::db.internal:3306::users",
                        "domain": "data",
                        "projection_confirmed": "realized",
                        "evidence_text": "db.internal measurement",
                    }),
                    json.dumps({
                        "workload_id": "mysql::db.internal:3306::users",
                        "domain": "data",
                        "projection_confirmed": "realized",
                        "evidence_text": "db.internal measurement",
                    }),
                ]) + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(forge_proposals, "SKG_STATE_DIR", state_dir):
                recall = forge_proposals._load_recall_adjustment(
                    domain="data",
                    hosts=["db.internal"],
                )

        self.assertEqual(recall["confirmed"], 3)
        self.assertEqual(recall["confirmation_rate"], 1.0)
        self.assertGreater(recall["delta"], 0.0)

    def test_project_event_file_supports_ai_toolchain(self):
        events = [
            {
                "id": "ai-1",
                "ts": "2026-03-15T00:00:00+00:00",
                "type": "obs.attack.precondition",
                "source": {
                    "source_id": "skg-ai-toolchain",
                    "toolchain": "skg-ai-toolchain",
                    "version": "1.0.0",
                },
                "payload": {
                    "wicket_id": "AI-01",
                    "status": "realized",
                    "attack_path_id": "ai_llm_extract_v1",
                    "run_id": "run-1",
                    "workload_id": "ai::10.0.0.8",
                    "detail": "Ollama service on :11434",
                },
                "provenance": {
                    "evidence_rank": 1,
                    "evidence": {
                        "source_kind": "http",
                        "pointer": "http://10.0.0.8:11434/api/tags",
                        "collected_at": "2026-03-15T00:00:00+00:00",
                        "confidence": 0.99,
                    },
                },
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            events_file = tmp / "ai.ndjson"
            interp_dir = tmp / "interp"
            with events_file.open("w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps(event) + "\n")

            outputs = project_event_file(events_file, interp_dir, run_id="run-1")
            self.assertEqual(len(outputs), 1)

            result = json.loads(outputs[0].read_text(encoding="utf-8"))
            self.assertEqual(result["attack_path_id"], "ai_llm_extract_v1")
            self.assertIn("ai_score", result)
            self.assertEqual(result["classification"], "indeterminate")
            self.assertEqual(result["classification_detail"], "partial")

    def test_surface_normalizes_legacy_projection_classifications(self):
        wrapped = {
            "id": "interp-ai-1",
            "type": "interp.ai.realizability",
            "payload": {
                "workload_id": "ai::10.0.0.8",
                "attack_path_id": "ai_llm_extract_v1",
                "classification": "fully_realized",
                "ai_score": 1.0,
                "realized": ["AI-01"],
                "blocked": [],
                "unknown": [],
                "computed_at": "2026-03-15T00:00:00+00:00",
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            interp_dir = Path(tmpdir)
            (interp_dir / "ai_ai__10_0_0_8_run-1.json").write_text(
                json.dumps(wrapped),
                encoding="utf-8",
            )
            rows = _read_interp_dir(interp_dir)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["classification"], "realized")

    def test_surface_exposes_fresh_view_separately_from_pearl_memory(self):
        import skg.intel.surface as surface_module

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            interp_dir = tmp / "interp"
            pearls_path = tmp / "pearls.jsonl"
            interp_dir.mkdir()

            (interp_dir / "host__10_0_0_7__host_ssh_initial_access_v1__run-1.json").write_text(
                json.dumps({
                    "workload_id": "host::10.0.0.7",
                    "attack_path_id": "host_ssh_initial_access_v1",
                    "classification": "indeterminate",
                    "host_score": 0.5,
                    "realized": ["HO-01"],
                    "blocked": [],
                    "unknown": ["HO-03"],
                    "computed_at": "2026-03-27T00:00:00+00:00",
                }),
                encoding="utf-8",
            )
            pearl = {
                "state_changes": [{"wicket_id": "HO-03"}],
                "observation_confirms": [{"wicket_id": "HO-03", "status": "realized"}],
                "projection_changes": [],
                "reason_changes": [],
                "observation_refs": [],
                "energy_snapshot": {
                    "workload_id": "host::10.0.0.7",
                    "domain": "host",
                    "manifestation_key": "host::10.0.0.7",
                },
                "target_snapshot": {
                    "workload_id": "host::10.0.0.7",
                    "domain": "host",
                },
                "fold_context": [],
                "timestamp": "2026-03-27T00:00:00+00:00",
            }
            pearls_path.write_text(
                json.dumps(pearl) + "\n" + json.dumps({**pearl, "timestamp": "2026-03-27T00:00:01+00:00"}),
                encoding="utf-8",
            )

            surf = surface_module.surface(interp_dir=interp_dir, pearls_path=pearls_path)

        row = surf["workloads"][0]
        self.assertTrue(row["fresh_view"])
        self.assertEqual(row["classification"], "indeterminate")
        self.assertEqual(row["measured_now"]["unknown"], ["HO-03"])
        self.assertEqual(row["memory_overlay"]["pearl_count"], 2)
        self.assertEqual(row["memory_overlay"]["reinforced_wickets"], ["HO-03"])
        self.assertEqual(surf["summary"]["memory_backed_workloads"], 1)
        self.assertEqual(surf["view_nodes"][0]["memory_overlay"]["reinforced_wickets"], ["HO-03"])

    def test_run_ssh_host_emits_connectivity_wickets_before_deeper_checks(self):
        def _fake_collect(
            client,
            *,
            host,
            out_path,
            attack_path_id,
            run_id,
            workload_id,
            username,
            auth_type,
            port,
        ):
            rows = [
                {"payload": {"wicket_id": "HO-01"}},
                {"payload": {"wicket_id": "HO-02"}},
                {"payload": {"wicket_id": "HO-03"}},
            ]
            out_path.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            return rows

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "events.ndjson"
            with mock.patch(
                "skg_services.gravity.host_runtime.collect_ssh_session_assessment_to_file",
                side_effect=_fake_collect,
            ):
                rows = adapter_runner.run_ssh_host(
                    client=object(),
                    host="172.17.0.3",
                    workload_id="ssh::172.17.0.3",
                    attack_path_id="host_ssh_initial_access_v1",
                    run_id="run-1",
                    out_file=out_file,
                    user="msfadmin",
                    auth_type="password",
                    port=22,
                )

        self.assertEqual(
            [row["payload"]["wicket_id"] for row in rows],
            ["HO-01", "HO-02", "HO-03"],
        )

    def test_gravity_precondition_event_uses_shared_subject_contract(self):
        gravity_field = _load_gravity_field_module()

        event = gravity_field._gravity_precondition_event(
            source_id="gravity.binary_analysis",
            toolchain="skg-binary-toolchain",
            wicket_id="BA-03",
            status="realized",
            workload_id="binary::192.168.254.5::ssh-keysign",
            target_ip="192.168.254.5",
            detail="stack cookie missing",
            evidence_rank=4,
            source_kind="binary_scanner",
            pointer="ssh://192.168.254.5",
            confidence=0.92,
            run_id="run-1",
            attack_path_id="binary_stack_overflow_v1",
            domain="binary",
            version="0.1.0",
            ts="2026-03-27T00:00:00+00:00",
            extra_payload={"observed_at": "2026-03-27T00:00:00+00:00"},
        )

        payload = event["payload"]
        self.assertEqual(event["type"], "obs.attack.precondition")
        self.assertEqual(event["source"]["toolchain"], "skg-binary-toolchain")
        self.assertEqual(payload["node_id"], "BA-03")
        self.assertEqual(payload["identity_key"], "192.168.254.5")
        self.assertEqual(payload["manifestation_key"], "binary::192.168.254.5::ssh-keysign")
        self.assertEqual(payload["target_ip"], "192.168.254.5")
        self.assertEqual(payload["attack_path_id"], "binary_stack_overflow_v1")

    def test_gravity_observation_coherence_uses_measured_view_domains(self):
        gravity_field = _load_gravity_field_module()

        coherence = gravity_field._instrument_observation_coherence(
            "binary_analysis",
            {
                "target": {
                    "domains": [],
                    "services": [],
                },
                "view_state": {
                    "measured_domains": ["binary_analysis"],
                    "view_count": 1,
                },
            },
        )

        self.assertEqual(coherence, 1.0)

    def test_gravity_observation_coherence_uses_observed_tool_hints(self):
        gravity_field = _load_gravity_field_module()

        coherence = gravity_field._instrument_observation_coherence(
            "binary_analysis",
            {
                "target": {
                    "domains": [],
                    "services": [],
                },
                "view_state": {
                    "measured_domains": [],
                    "view_count": 1,
                    "observed_tools": {
                        "tool_names": ["checksec"],
                        "observed_tools": [
                            {
                                "name": "checksec",
                                "instrument_names": ["binary_analysis"],
                                "domain_hints": ["binary"],
                            }
                        ],
                        "domain_hints": ["binary"],
                        "instrument_hints": ["binary_analysis"],
                        "scope": "node_local",
                        "status": "realized",
                    },
                },
            },
        )

        self.assertEqual(coherence, 0.85)

    def test_gravity_observed_tool_summary_includes_nse_and_hints(self):
        gravity_field = _load_gravity_field_module()

        summary = gravity_field._observed_tool_summary({
            "observed_tools": {
                "tool_names": ["checksec", "nmap"],
                "observed_tools": [
                    {
                        "name": "nmap",
                        "nse_available": True,
                    }
                ],
                "instrument_hints": ["binary_analysis", "nmap"],
                "nse_available": True,
                "nse_script_count": 612,
            }
        })

        self.assertIn("checksec", summary)
        self.assertIn("nmap (NSE=612)", summary)
        self.assertIn("hints: binary_analysis, nmap", summary)

    def test_gravity_subject_rows_include_measured_only_identity(self):
        gravity_field = _load_gravity_field_module()

        rows = gravity_field._gravity_subject_rows(
            {"targets": []},
            {
                "192.168.254.5": {
                    "identity_key": "192.168.254.5",
                    "view_count": 1,
                    "measured_domains": ["binary_analysis"],
                    "measured_unknowns": 2.0,
                }
            },
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity_key"], "192.168.254.5")
        self.assertEqual(rows[0]["ip"], "192.168.254.5")
        self.assertEqual(rows[0]["view_state"]["measured_domains"], ["binary_analysis"])
        self.assertTrue(rows[0]["target"]["_synthetic_from_view"])
        self.assertEqual(rows[0]["target"]["domains"], ["binary_analysis"])

    def test_gravity_fold_identity_key_uses_stable_subject_identity(self):
        gravity_field = _load_gravity_field_module()
        from skg.kernel.folds import Fold

        fold = Fold(
            fold_type="contextual",
            location="binary::192.168.254.5::ssh-keysign",
            constraint_source="nvd_feed::CVE-2026-9999",
        )

        self.assertEqual(gravity_field._fold_identity_key(fold), "192.168.254.5")

    def test_persisted_fold_managers_merge_by_identity_key(self):
        gravity_field = _load_gravity_field_module()
        from skg.kernel.folds import Fold, FoldManager

        with tempfile.TemporaryDirectory() as td:
            folds_dir = Path(td)

            first = FoldManager()
            first.add(Fold(
                fold_type="projection",
                location="binary::192.168.254.5::ssh-keysign",
                constraint_source="gap::missing_path::binary_stack_overflow_v1",
            ))
            first.persist(folds_dir / "folds_projection.json")

            second = FoldManager()
            second.add(Fold(
                fold_type="contextual",
                location="cve::192.168.254.5",
                constraint_source="nvd_feed::CVE-2026-1111",
                why={"target_ip": "192.168.254.5"},
            ))
            second.persist(folds_dir / "folds_contextual.json")

            loaded = gravity_field._load_persisted_fold_managers(folds_dir)

        self.assertEqual(set(loaded.keys()), {"192.168.254.5"})
        self.assertEqual(len(loaded["192.168.254.5"].all()), 2)

    def test_project_event_file_supports_data_toolchain(self):
        events = [
            {
                "id": "dp-1",
                "ts": "2026-03-17T00:00:00+00:00",
                "type": "obs.attack.precondition",
                "source": {
                    "source_id": "adapter.db_profiler",
                    "toolchain": "skg-data-toolchain",
                    "version": "0.1.0",
                },
                "payload": {
                    "wicket_id": "DP-01",
                    "status": "realized",
                    "attack_path_id": "data_completeness_failure_v1",
                    "run_id": "run-1",
                    "workload_id": "mysql::172.17.0.3:3306::dvwa.users",
                },
                "provenance": {
                    "evidence_rank": 1,
                    "evidence": {
                        "source_kind": "db_profiler_runtime",
                        "pointer": "mysql://172.17.0.3:3306/dvwa.users",
                        "collected_at": "2026-03-17T00:00:00+00:00",
                        "confidence": 0.95,
                    },
                },
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            events_file = tmp / "data.ndjson"
            interp_dir = tmp / "interp"
            with events_file.open("w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps(event) + "\n")

            outputs = project_event_file(events_file, interp_dir, run_id="run-1")
            self.assertEqual(len(outputs), 1)

            result = json.loads(outputs[0].read_text(encoding="utf-8"))
            self.assertNotIn("payload", result)
            self.assertEqual(result["attack_path_id"], "data_completeness_failure_v1")
            self.assertIn("data_score", result)

    def test_project_event_file_supports_iot_supply_chain_and_binary_toolchains(self):
        cases = [
            (
                "iot.ndjson",
                {
                    "source_id": "adapter.iot",
                    "toolchain": "skg-iot_firmware-toolchain",
                    "wicket_id": "IF-01",
                    "attack_path_id": "iot_firmware_network_exploit_v1",
                    "workload_id": "iot::192.168.0.10",
                },
                "iot_score",
                "iot_firmware_network_exploit_v1",
            ),
            (
                "supply.ndjson",
                {
                    "source_id": "adapter.supply",
                    "toolchain": "skg-supply-chain-toolchain",
                    "wicket_id": "SC-01",
                    "attack_path_id": "supply_chain_rce_via_dependency_v1",
                    "workload_id": "supply_chain::172.17.0.3",
                },
                "supply_chain_score",
                "supply_chain_network_exploit_v1",
            ),
            (
                "binary.ndjson",
                {
                    "source_id": "adapter.binary",
                    "toolchain": "skg-binary-toolchain",
                    "wicket_id": "BA-01",
                    "attack_path_id": "binary_stack_overflow_v1",
                    "workload_id": "binary::172.17.0.3",
                },
                "binary_score",
                "binary_stack_overflow_v1",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            interp_dir = tmp / "interp"
            for filename, meta, score_key, expected_path_id in cases:
                event = {
                    "id": f"{meta['wicket_id']}-1",
                    "ts": "2026-03-17T00:00:00+00:00",
                    "type": "obs.attack.precondition",
                    "source": {
                        "source_id": meta["source_id"],
                        "toolchain": meta["toolchain"],
                        "version": "0.1.0",
                    },
                    "payload": {
                        "wicket_id": meta["wicket_id"],
                        "status": "realized",
                        "attack_path_id": meta["attack_path_id"],
                        "run_id": "run-1",
                        "workload_id": meta["workload_id"],
                    },
                    "provenance": {
                        "evidence_rank": 1,
                        "evidence": {
                            "source_kind": "test",
                            "pointer": "test://projection",
                            "collected_at": "2026-03-17T00:00:00+00:00",
                            "confidence": 0.95,
                        },
                    },
                }
                events_file = tmp / filename
                events_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

                outputs = project_event_file(events_file, interp_dir, run_id="run-1")
                self.assertEqual(len(outputs), 1)
                result = json.loads(outputs[0].read_text(encoding="utf-8"))
                self.assertNotIn("payload", result)
                self.assertEqual(result["attack_path_id"], expected_path_id)
                self.assertIn(score_key, result)

    def test_project_event_file_supports_ad_legacy_attack_path_alias(self):
        event = {
            "id": "ad-1",
            "ts": "2026-03-17T00:00:00+00:00",
            "type": "obs.attack.precondition",
            "source": {
                "source_id": "adapter.bloodhound",
                "toolchain": "skg-ad-lateral-toolchain",
                "version": "0.1.0",
            },
            "payload": {
                "wicket_id": "AD-01",
                "status": "realized",
                "attack_path_id": "ad_lateral_movement_v1",
                "run_id": "run-1",
                "workload_id": "ad::10.0.0.5",
            },
            "provenance": {
                "evidence_rank": 1,
                "evidence": {
                    "source_kind": "test",
                    "pointer": "test://bloodhound",
                    "collected_at": "2026-03-17T00:00:00+00:00",
                    "confidence": 0.95,
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            events_file = tmp / "ad.ndjson"
            interp_dir = tmp / "interp"
            events_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

            outputs = project_event_file(events_file, interp_dir, run_id="run-1")
            self.assertEqual(len(outputs), 1)
            wrapped = json.loads(outputs[0].read_text(encoding="utf-8"))
            result = wrapped.get("payload", wrapped)
            self.assertEqual(result["attack_path_id"], "ad_kerberoast_v1")
            self.assertIn("lateral_score", result)

    def test_surface_infers_new_projection_domains(self):
        payloads = [
            (
                "supply_chain_supply_chain__172.17.0.3_run-1.json",
                {
                    "payload": {
                        "workload_id": "supply_chain::172.17.0.3",
                        "attack_path_id": "supply_chain_network_exploit_v1",
                        "classification": "indeterminate",
                        "supply_chain_score": 0.25,
                        "realized": ["SC-01"],
                        "blocked": [],
                        "unknown": ["SC-03"],
                        "computed_at": "2026-03-17T00:00:00+00:00",
                    }
                },
            ),
            (
                "iot_firmware_iot__192.168.254.1_run-1.json",
                {
                    "payload": {
                        "workload_id": "iot::192.168.254.1",
                        "attack_path_id": "iot_firmware_network_exploit_v1",
                        "classification": "indeterminate",
                        "iot_score": 0.0,
                        "realized": [],
                        "blocked": [],
                        "unknown": ["IF-01"],
                        "computed_at": "2026-03-17T00:00:00+00:00",
                    }
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            interp_dir = Path(tmpdir)
            for filename, payload in payloads:
                (interp_dir / filename).write_text(json.dumps(payload), encoding="utf-8")
            surf = surface(interp_dir)

        by_workload = {row["workload_id"]: row for row in surf["workloads"]}
        self.assertEqual(by_workload["supply_chain::172.17.0.3"]["domain"], "supply_chain")
        self.assertEqual(by_workload["iot::192.168.254.1"]["domain"], "iot_firmware")

    def test_create_catalog_growth_proposal_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pending = root / "pending"
            accepted = root / "accepted"
            rejected = root / "rejected"
            memory = []

            class FakeLedger:
                def record(self, pearl):
                    memory.append(pearl)

            with mock.patch.object(forge_proposals, "PROPOSALS_DIR", pending), \
                 mock.patch.object(forge_proposals, "ACCEPTED_DIR", accepted), \
                 mock.patch.object(forge_proposals, "REJECTED_DIR", rejected), \
                 mock.patch.object(forge_proposals, "_proposal_pearl_ledger", return_value=FakeLedger()):
                proposal = forge_proposals.create_catalog_growth(
                    domain="web",
                    description="CVE-derived fold suggests missing web wicket coverage",
                    hosts=["172.17.0.3"],
                    attack_surface="Apache/PHP path suggests unmapped CVE coverage gap",
                    evidence="172.17.0.3:web:catalog_growth:fold-1\n- Apache 2.4 CVE signal",
                    compiler_hints={"packages": ["apache"], "keywords": ["CVE-2026-0001", "apache"]},
                    fold_ids=["fold-1"],
                    command="skg catalog compile --domain web --dry-run --keywords CVE-2026-0001 --keywords apache",
                )
                self.assertEqual(proposal["proposal_kind"], "catalog_growth")
                self.assertEqual(proposal["action"]["instrument"], "catalog_compiler")
                self.assertIn("--dry-run", proposal["action"]["command"])
                self.assertIn("growth_memory", proposal["recall"])
                self.assertEqual(len(memory), 1)
                self.assertEqual(memory[0].reason_changes[0]["reason"], "proposal_created")

                accepted_result = forge_proposals.accept(proposal["id"])
                self.assertTrue(accepted_result["accepted"])
                self.assertEqual(accepted_result["proposal_kind"], "catalog_growth")
                self.assertIn("--dry-run", accepted_result["command"])
                self.assertTrue((accepted / f"{proposal['id']}.json").exists())

    def test_forge_pipeline_emits_mc03_trigger_and_reviewable_growth_proposal(self):
        from skg.forge import pipeline as forge_pipeline

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            events_dir = root / "events"
            pending = root / "pending"
            signal_dir = root / "metacognition"
            cognitive_signal_dir = root / "cognitive"
            staged = root / "staged-toolchain"
            events_dir.mkdir(parents=True, exist_ok=True)
            staged.mkdir(parents=True, exist_ok=True)

            gap = {
                "service": "redis",
                "category": "process",
                "hosts": ["172.17.0.3"],
                "evidence": "redis-server process observed",
                "detail": "Running service with no toolchain coverage",
                "attack_surface": "Unauthenticated access and config rewrite",
                "collection_hints": ["redis-cli -h {host} ping"],
                "forge_ready": True,
            }

            with mock.patch("skg.intel.gap_detector.detect_new_gaps", return_value=[gap]), \
                 mock.patch("skg.forge.generator.generate_toolchain", return_value={
                     "success": True,
                     "staging_path": str(staged),
                     "wicket_count": 3,
                     "path_count": 1,
                     "generation_backend": "template",
                     "errors": [],
                 }), \
                 mock.patch("skg.forge.validator.validate", return_value={"passed": True, "checks": {}}), \
                 mock.patch.object(forge_pipeline, "METACOGNITION_SIGNAL_DIR", signal_dir), \
                 mock.patch.object(forge_pipeline, "COGNITIVE_SIGNAL_DIR", cognitive_signal_dir), \
                 mock.patch.object(forge_proposals, "PROPOSALS_DIR", pending):
                summary = forge_pipeline.run_forge_pipeline(events_dir=events_dir)

            self.assertEqual(summary["gaps_detected"], 1)
            self.assertEqual(summary["mc03_realized"], 1)
            self.assertEqual(summary["cp01_generated"], 1)
            self.assertEqual(summary["proposed"], 1)
            self.assertTrue(summary["mc03_signal_file"])

            signal_files = sorted(signal_dir.glob("*.ndjson"))
            self.assertEqual(len(signal_files), 1)
            signal_lines = signal_files[0].read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(signal_lines), 1)
            signal = json.loads(signal_lines[0])
            self.assertEqual(signal["signal_id"], "MC-03")
            self.assertEqual(signal["label"], "coverage_gap_detected")
            self.assertEqual(signal["service"], "redis")
            self.assertEqual(signal["status"], "realized")

            cp_files = sorted(cognitive_signal_dir.glob("*.ndjson"))
            self.assertEqual(len(cp_files), 1)
            cp_lines = cp_files[0].read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(cp_lines), 1)
            cp_signal = json.loads(cp_lines[0])
            self.assertEqual(cp_signal["signal_id"], "CP-01")
            self.assertEqual(cp_signal["label"], "toolchain_candidate_generated")
            self.assertEqual(cp_signal["service"], "redis")

            proposal_files = sorted(pending.glob("*.json"))
            self.assertEqual(len(proposal_files), 1)
            proposal = json.loads(proposal_files[0].read_text(encoding="utf-8"))
            self.assertEqual(proposal["proposal_kind"], "toolchain_generation")
            self.assertEqual(proposal["domain"], "redis")
            self.assertEqual(proposal["metacognition_trigger"]["signal_id"], "MC-03")
            self.assertEqual(proposal["metacognition_trigger"]["service"], "redis")
            self.assertEqual(proposal["substrate_trigger"]["signal_id"], "MC-03")
            self.assertEqual(proposal["cognitive_signal"]["signal_id"], "CP-01")

    def test_toolchain_generation_proposal_detail_shows_metacognition_trigger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pending = Path(tmpdir) / "pending"
            with mock.patch.object(forge_proposals, "PROPOSALS_DIR", pending):
                proposal = forge_proposals.create(
                    domain="redis",
                    description="Coverage gap suggests missing Redis expression",
                    gap={
                        "service": "redis",
                        "hosts": ["172.17.0.3"],
                        "attack_surface": "Unauthenticated access and config rewrite",
                        "category": "process",
                        "evidence": "redis-server process observed",
                        "metacognition_trigger": {
                            "signal_id": "MC-03",
                            "label": "coverage_gap_detected",
                            "service": "redis",
                            "detail": "Coverage gap detected for redis",
                        },
                        "cognitive_signal": {
                            "signal_id": "CP-01",
                            "label": "toolchain_candidate_generated",
                            "detail": "Candidate toolchain for redis generated and staged for operator review.",
                        },
                    },
                    generation_result={
                        "staging_path": str(Path(tmpdir) / "staged"),
                        "wicket_count": 2,
                        "path_count": 1,
                        "generation_backend": "template",
                        "errors": [],
                    },
                    validation_result={"passed": True, "checks": {}},
                )

            detail = forge_proposals.format_proposal_detail(proposal)
            self.assertIn("Metacognition:", detail)
            self.assertIn("MC-03 coverage_gap_detected", detail)
            self.assertIn("Coverage gap detected for redis", detail)
            self.assertIn("Cognitive Signal:", detail)
            self.assertIn("CP-01 toolchain_candidate_generated", detail)

    def test_supersede_catalog_growth_archives_and_records_memory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pending = root / "pending"
            accepted = root / "accepted"
            rejected = root / "rejected"
            superseded = root / "superseded"
            memory = []

            class FakeLedger:
                def record(self, pearl):
                    memory.append(pearl)

            with mock.patch.object(forge_proposals, "PROPOSALS_DIR", pending), \
                 mock.patch.object(forge_proposals, "ACCEPTED_DIR", accepted), \
                 mock.patch.object(forge_proposals, "REJECTED_DIR", rejected), \
                 mock.patch.object(forge_proposals, "SUPERSEDED_DIR", superseded), \
                 mock.patch.object(forge_proposals, "_proposal_pearl_ledger", return_value=FakeLedger()):
                proposal = forge_proposals.create_catalog_growth(
                    domain="web",
                    description="legacy single-fold growth item",
                    hosts=["172.17.0.3"],
                    evidence="172.17.0.3:web:catalog_growth:fold-legacy",
                    compiler_hints={"packages": ["apache"], "keywords": ["CVE-2026-0001"]},
                    fold_ids=["fold-legacy"],
                    command="skg catalog compile --domain web --description legacy --dry-run --keywords CVE-2026-0001",
                )
                result = forge_proposals.supersede(
                    [proposal["id"]],
                    replacement_id="cluster-1",
                    reason="clustered_catalog_growth",
                )

            self.assertEqual(result["superseded"], 1)
            self.assertTrue((superseded / f"{proposal['id']}.json").exists())
            self.assertFalse((pending / f"{proposal['id']}.json").exists())
            self.assertEqual(len(memory), 2)
            self.assertEqual(memory[0].reason_changes[0]["reason"], "proposal_created")
            self.assertEqual(memory[1].reason_changes[0]["reason"], "clustered_catalog_growth")
            self.assertEqual(memory[1].reason_changes[0]["replacement_id"], "cluster-1")

    def test_catalog_growth_command_handles_non_cve_contextual_fold(self):
        gravity_field = _load_gravity_field_module()

        class FoldStub:
            fold_type = "contextual"
            detail = "Observed Apache DAV configuration is not represented in the current web catalog"
            why = {"service": "Apache/2.4.25 (Debian) DAV/2"}

        command, description = gravity_field._catalog_growth_command_for_fold(
            "web",
            FoldStub(),
            {"packages": ["apache"], "keywords": ["apache", "dav"]},
        )
        self.assertIn("skg catalog compile", command)
        self.assertIn("--description", command)
        self.assertIn("--packages apache", command)
        self.assertIn("--keywords apache,dav", command)
        self.assertIn("Apache DAV", description)

    def test_catalog_growth_proposals_include_projection_folds(self):
        gravity_field = _load_gravity_field_module()

        class FoldStub:
            def __init__(self):
                self.fold_type = "projection"
                self.discovery_probability = 0.8
                self.id = "fold-proj-1"
                self.detail = "jenkins observed at 10.0.0.5 but attack path 'jenkins_groovy_rce_v1' is not catalogued"
                self.constraint_source = "gap::missing_path::jenkins_groovy_rce_v1::10.0.0.5"
                self.why = {
                    "service": "jenkins",
                    "attack_path_id": "jenkins_groovy_rce_v1",
                }

        class FoldManagerStub:
            def all(self):
                return [FoldStub()]

        captured = []

        def fake_create_catalog_growth(**kwargs):
            captured.append(kwargs)
            return {"id": "proposal-1"}

        with mock.patch.object(forge_proposals, "proposals_for_dedupe", return_value=[]), \
             mock.patch.object(forge_proposals, "is_in_cooldown", return_value=False), \
             mock.patch.object(forge_proposals, "create_catalog_growth", side_effect=fake_create_catalog_growth):
            created = gravity_field._create_catalog_growth_proposals_from_folds(
                {"10.0.0.5": FoldManagerStub()}
            )

        self.assertEqual(created, ["proposal-1"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["category"], "projection_fold_cluster")
        self.assertEqual(captured[0]["domain"], "web")
        self.assertIn("jenkins_groovy_rce_v1", captured[0]["command"])
        self.assertIn("--description", captured[0]["command"])

    def test_catalog_growth_proposals_preserve_identity_hosts(self):
        gravity_field = _load_gravity_field_module()

        class FoldStub:
            fold_type = "projection"
            discovery_probability = 0.8
            id = "fold-proj-hostname"
            detail = "jenkins observed at dc01.corp.local but attack path 'jenkins_groovy_rce_v1' is not catalogued"
            constraint_source = "gap::missing_path::jenkins_groovy_rce_v1::dc01.corp.local"
            why = {
                "service": "jenkins",
                "attack_path_id": "jenkins_groovy_rce_v1",
            }

        class FoldManagerStub:
            def all(self):
                return [FoldStub()]

        captured = []

        def fake_create_catalog_growth(**kwargs):
            captured.append(kwargs)
            return {"id": "proposal-hostname"}

        with mock.patch.object(forge_proposals, "proposals_for_dedupe", return_value=[]), \
             mock.patch.object(forge_proposals, "is_in_cooldown", return_value=False), \
             mock.patch.object(forge_proposals, "create_catalog_growth", side_effect=fake_create_catalog_growth):
            created = gravity_field._create_catalog_growth_proposals_from_folds(
                {"dc01.corp.local": FoldManagerStub()}
            )

        self.assertEqual(created, ["proposal-hostname"])
        self.assertEqual(captured[0]["hosts"], ["dc01.corp.local"])

    def test_catalog_growth_proposals_cluster_related_contextual_folds(self):
        gravity_field = _load_gravity_field_module()

        class FoldStub:
            def __init__(self, fold_id, cve_id):
                self.fold_type = "contextual"
                self.discovery_probability = 0.8
                self.id = fold_id
                self.detail = (
                    f"{cve_id} has no wicket mapping. Service: Apache/2.4.25 (Debian). "
                    f"CVSS: 9.8. Create a wicket with: skg catalog compile --domain <domain> --keywords {cve_id}"
                )
                self.constraint_source = f"nvd_feed::{cve_id}"
                self.why = {"service": "Apache/2.4.25 (Debian)", "cve_id": cve_id}

        class FoldManagerStub:
            def all(self):
                return [
                    FoldStub("fold-1", "CVE-2017-3167"),
                    FoldStub("fold-2", "CVE-2017-3169"),
                ]

        captured = []

        def fake_create_catalog_growth(**kwargs):
            captured.append(kwargs)
            return {"id": "proposal-cluster"}

        with mock.patch.object(forge_proposals, "proposals_for_dedupe", return_value=[]), \
             mock.patch.object(forge_proposals, "is_in_cooldown", return_value=False), \
             mock.patch.object(forge_proposals, "create_catalog_growth", side_effect=fake_create_catalog_growth):
            created = gravity_field._create_catalog_growth_proposals_from_folds(
                {"172.18.0.1": FoldManagerStub()}
            )

        self.assertEqual(created, ["proposal-cluster"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["category"], "contextual_fold_cluster")
        self.assertEqual(captured[0]["fold_ids"], ["fold-1", "fold-2"])
        self.assertIn("CVE-2017-3167", captured[0]["command"])
        self.assertIn("CVE-2017-3169", captured[0]["command"])
        self.assertIn("--keywords", captured[0]["command"])

    def test_catalog_growth_dedupe_sees_hidden_deferred_proposals(self):
        gravity_field = _load_gravity_field_module()

        class FoldStub:
            fold_type = "contextual"
            discovery_probability = 0.95
            id = "fold-deferred"
            detail = (
                "CVE-2017-3167 has no wicket mapping. Service: Apache/2.4.25 (Debian). "
                "CVSS: 9.8. Create a wicket with: skg catalog compile --domain <domain> --keywords CVE-2017-3167"
            )
            constraint_source = "nvd_feed::CVE-2017-3167"
            why = {"service": "Apache/2.4.25 (Debian)", "cve_id": "CVE-2017-3167"}

        class FoldManagerStub:
            def all(self):
                return [FoldStub()]

        deferred = {
            "id": "existing-deferred",
            "proposal_kind": "catalog_growth",
            "domain": "web",
            "status": "deferred",
            "defer_until": "2099-01-01T00:00:00+00:00",
            "hosts": ["192.168.254.5"],
            "evidence": "192.168.254.5:web:catalog_growth:apache:contextual\n- existing",
        }

        with mock.patch.object(forge_proposals, "proposals_for_dedupe", return_value=[deferred]), \
             mock.patch.object(forge_proposals, "is_in_cooldown", return_value=False), \
             mock.patch.object(
                 forge_proposals,
                 "create_catalog_growth",
                 side_effect=AssertionError("duplicate proposal should not be created"),
             ):
            created = gravity_field._create_catalog_growth_proposals_from_folds(
                {"192.168.254.5": FoldManagerStub()}
            )

        self.assertEqual(created, [])

    def test_catalog_growth_dedupe_ignores_expired_history(self):
        gravity_field = _load_gravity_field_module()

        class FoldStub:
            fold_type = "contextual"
            discovery_probability = 0.95
            id = "fold-expired"
            detail = (
                "CVE-2017-3167 has no wicket mapping. Service: Apache/2.4.25 (Debian). "
                "CVSS: 9.8. Create a wicket with: skg catalog compile --domain <domain> --keywords CVE-2017-3167"
            )
            constraint_source = "nvd_feed::CVE-2017-3167"
            why = {"service": "Apache/2.4.25 (Debian)", "cve_id": "CVE-2017-3167"}

        class FoldManagerStub:
            def all(self):
                return [FoldStub()]

        expired = {
            "id": "existing-expired",
            "proposal_kind": "catalog_growth",
            "domain": "web",
            "status": "expired",
            "hosts": ["172.17.0.3"],
            "evidence": "172.17.0.3:web:catalog_growth:apache:contextual\n- existing",
        }
        captured = []

        def fake_create_catalog_growth(**kwargs):
            captured.append(kwargs)
            return {"id": "proposal-new"}

        with mock.patch.object(forge_proposals, "proposals_for_dedupe", return_value=[expired]), \
             mock.patch.object(forge_proposals, "is_in_cooldown", return_value=False), \
             mock.patch.object(forge_proposals, "create_catalog_growth", side_effect=fake_create_catalog_growth):
            created = gravity_field._create_catalog_growth_proposals_from_folds(
                {"172.17.0.3": FoldManagerStub()}
            )

        self.assertEqual(created, ["proposal-new"])
        self.assertEqual(len(captured), 1)

    def test_nvd_service_candidates_use_target_inventory_before_wb02_only_detail(self):
        gravity_field = _load_gravity_field_module()

        target = {
            "services": [
                {
                    "service": "ssh",
                    "banner": "OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0",
                },
                {
                    "service": "http",
                    "banner": "Apache httpd 2.2.8 ((Ubuntu) DAV/2)",
                },
                {
                    "service": "mysql",
                    "banner": "MySQL 5.0.51a-3ubuntu5",
                },
            ]
        }

        with mock.patch.object(
            gravity_field,
            "load_wicket_states",
            return_value={"WB-02": {"detail": json.dumps({"server": "Apache/2.2.8"})}},
        ):
            candidates = gravity_field._nvd_service_candidates("172.17.0.3", target)

        self.assertIn("OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0", candidates)
        self.assertIn("Apache httpd 2.2.8 ((Ubuntu) DAV/2)", candidates)
        self.assertIn("MySQL 5.0.51a-3ubuntu5", candidates)
        self.assertIn("Apache/2.2.8", candidates)

    def test_nvd_service_candidates_fall_back_to_wb02_when_target_inventory_is_thin(self):
        gravity_field = _load_gravity_field_module()

        with mock.patch.object(
            gravity_field,
            "load_wicket_states",
            return_value={"WB-02": {"detail": json.dumps({"server": "Apache/2.4.25", "x-powered-by": "PHP/7.0.33"})}},
        ):
            candidates = gravity_field._nvd_service_candidates("192.168.254.5", {"services": []})

        self.assertEqual(candidates, ["Apache/2.4.25", "PHP/7.0.33"])

    def test_identity_world_derives_access_paths_from_services_and_profile(self):
        daemon = _load_daemon_module()
        target = {
            "ip": "172.17.0.3",
            "services": [
                {"port": 22, "service": "ssh", "banner": "OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0"},
                {"port": 3306, "service": "mysql", "banner": "MySQL 5.0.51a-3ubuntu5"},
                {"port": 80, "service": "http", "banner": "Apache 2.2.8"},
            ],
            "domains": ["host", "web", "data"],
        }
        profile = {
            "users": ["msfadmin"],
            "groups": ["admin"],
            "id_output": "uid=1000(msfadmin)",
            "passwd_samples": ["root:x:0:0:root:/root:/bin/bash"],
            "credential_indicators": ["env"],
            "env_key_samples": ["PWD"],
            "ssh_keys": ["/home/msfadmin/.ssh/id_rsa"],
            "sudo_state": "sudo available",
            "package_manager": "dpkg",
            "package_count": 200,
            "packages_sample": ["apache2 2.2.8-1ubuntu0.15"],
            "process_count": 54,
            "process_findings": [{"wicket_id": "PI-01", "detail": "1 new process(es) not in manifest: in.telnetd"}],
            "docker_access": True,
            "datastore_access": ["MySQL accessible as root — database access confirmed"],
            "datastore_observations": [
                {
                    "service": "mysql",
                    "workload_id": "mysql::172.17.0.3:3306::dvwa.users",
                    "detail": "MySQL accessible as root — database access confirmed",
                }
            ],
            "network_findings": [
                {
                    "wicket_id": "WB-08",
                    "detail": "Authenticated scan aborted — target unreachable: connect: [Errno 113] No route to host",
                    "pointer": "http://172.17.0.3:80",
                }
            ],
            "network_flows": [
                {"protocol": "TCP", "src": "172.17.0.1", "dst": "172.17.0.3", "port": 22},
                {"protocol": "TCP", "src": "172.17.0.3", "dst": "169.254.169.254", "port": 80},
            ],
            "listening_baseline": "0 ports",
            "container": {},
            "notes": [],
            "evidence_count": 6,
            "kernel_version": None,
            "interesting_suid": [],
            "av_edr": None,
            "domain_membership": None,
        }

        with mock.patch.object(daemon, "_identity_profile", return_value=profile), \
             mock.patch.object(daemon, "_identity_manifestations", return_value=[]), \
             mock.patch.object(daemon, "_identity_relations", return_value=[]):
            world = daemon._identity_world("172.17.0.3", target)

        self.assertEqual(world["principals"]["users"], ["msfadmin"])
        self.assertIn("root:x:0:0:root:/root:/bin/bash", world["principals"]["passwd_samples"])
        self.assertEqual(world["runtime"]["process_count"], 54)
        self.assertEqual(world["runtime"]["process_findings"][0]["wicket_id"], "PI-01")
        self.assertIn("apache2 2.2.8-1ubuntu0.15", world["runtime"]["packages_sample"])
        self.assertEqual(world["datastore_access"], ["MySQL accessible as root — database access confirmed"])
        self.assertGreaterEqual(world["world_summary"]["credential_binding_count"], 1)
        self.assertEqual(world["world_summary"]["inbound_peer_count"], 1)
        self.assertEqual(world["world_summary"]["outbound_peer_count"], 1)

        access = world["access_paths"]
        ssh_row = next(row for row in access if row["kind"] == "remote_access" and row["service"] == "ssh")
        self.assertIn("msfadmin", ssh_row["credential_candidates"])
        self.assertIn("/home/msfadmin/.ssh/id_rsa", ssh_row["credential_candidates"])

        mysql_row = next(row for row in access if row["kind"] == "datastore" and row["service"] == "mysql")
        self.assertIn("MySQL accessible as root", mysql_row["confirmed_access"][0])
        http_row = next(row for row in access if row["kind"] == "remote_access" and row["service"] == "ssh")
        self.assertEqual(http_row["network_constraints"], [])

        runtime_row = next(row for row in access if row["kind"] == "runtime_control")
        self.assertEqual(runtime_row["service"], "docker")
        self.assertEqual(world["network"]["findings"][0]["wicket_id"], "WB-08")
        ssh_binding = next(row for row in world["credentials"]["bindings"] if row["service"] == "ssh")
        self.assertIn("observed ssh key material", ssh_binding["rationale"])
        self.assertEqual(world["network"]["inbound_peers"][0]["peer"], "172.17.0.1")
        self.assertEqual(world["network"]["outbound_peers"][0]["peer"], "169.254.169.254")
        self.assertEqual(world["network"]["listening_baseline"], "0 ports")

    def test_latest_matching_files_keeps_newest_from_each_pattern_family(self):
        daemon = _load_daemon_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            family_a = []
            family_b = []
            for idx in range(5):
                pa = tmp / f"a_{idx}.ndjson"
                pb = tmp / f"b_{idx}.ndjson"
                pa.write_text("a", encoding="utf-8")
                pb.write_text("b", encoding="utf-8")
                ts = 1000 + idx
                os.utime(pa, (ts, ts))
                os.utime(pb, (ts + 100, ts + 100))
                family_a.append(str(pa))
                family_b.append(str(pb))

            picked = daemon._latest_matching_files(
                [str(tmp / "a_*.ndjson"), str(tmp / "b_*.ndjson")],
                limit=4,
                per_pattern=1,
            )

        self.assertEqual(len(picked), 2)
        self.assertIn(str(tmp / "a_4.ndjson"), picked)
        self.assertIn(str(tmp / "b_4.ndjson"), picked)

    def test_field_topology_decomposition_surfaces_protected_and_curved_spheres(self):
        host = SphereEnergy(
            sphere="host",
            G=0.9,
            G_norm=0.85,
            n_wickets=4,
            n_realized=4,
            n_blocked=0,
            n_unknown=0,
            unknown_mass=0.0,
            total_local_energy=0.2,
            mean_local_energy=0.05,
            n_latent=0,
        )
        web = SphereEnergy(
            sphere="web",
            G=0.2,
            G_norm=0.3,
            n_wickets=5,
            n_realized=1,
            n_blocked=1,
            n_unknown=3,
            unknown_mass=3.8,
            total_local_energy=2.4,
            mean_local_energy=0.8,
            n_latent=1,
        )

        topo = decompose_field_topology(
            sphere_energies={"host": host, "web": web},
            coupling={"host": {"web": 0.6}, "web": {"host": 0.6}},
            fiber_tension={"host": 0.0, "web": 0.0},
            pearl_persistence={"host": 0.0, "web": 0.0},
            beta_1=1,
            h1_obstruction_count=1,
        )

        self.assertIn("host", topo.protected_spheres)
        self.assertTrue(topo.spheres["host"].protected_state)
        self.assertGreater(topo.spheres["web"].curvature, topo.spheres["host"].curvature)
        self.assertGreater(topo.total_coupling_energy, 0.0)
        self.assertGreaterEqual(topo.global_curvature, 2.0)

    def test_topology_sphere_map_matches_canonical_wicket_prefixes(self):
        self.assertEqual(_sphere_for_wicket("HO-01"), "host")
        self.assertEqual(_sphere_for_wicket("PI-01"), "host")
        self.assertEqual(_sphere_for_wicket("LI-01"), "host")
        self.assertEqual(_sphere_for_wicket("WB-01"), "web")
        self.assertEqual(_sphere_for_wicket("DP-01"), "data")
        self.assertEqual(_sphere_for_wicket("BA-01"), "binary")
        self.assertEqual(_sphere_for_wicket("AI-01"), "ai_target")
        self.assertEqual(_sphere_for_wicket("IF-01"), "iot_firmware")
        self.assertEqual(_sphere_for_wicket("SC-01"), "supply_chain")
        self.assertEqual(_sphere_for_wicket("ZZ-01"), "unknown")

    def test_compute_sphere_energy_tracks_unknown_mass_not_only_count(self):
        states = [
            WicketState(
                wicket_id="WB-01",
                status="unknown",
                confidence=0.8,
                confidence_vector=[0.8],
                local_energy=0.6,
                decoherence=0.4,
                compatibility_score=0.5,
            ),
            WicketState(
                wicket_id="WB-02",
                status="unknown",
                confidence=0.3,
                confidence_vector=[0.3],
                local_energy=0.2,
                decoherence=0.0,
                compatibility_score=0.0,
            ),
        ]

        energy = compute_sphere_energy(states, "web")

        self.assertEqual(energy.n_unknown, 2)
        self.assertAlmostEqual(energy.unknown_mass, 2.075, places=6)
        self.assertGreater(energy.unknown_mass, 0.0)

    def test_field_topology_prefers_unknown_mass_over_unknown_count(self):
        web = SphereEnergy(
            sphere="web",
            G=0.2,
            G_norm=0.3,
            n_wickets=5,
            n_realized=1,
            n_blocked=1,
            n_unknown=9,
            unknown_mass=4.85,
            total_local_energy=0.0,
            mean_local_energy=0.0,
            n_latent=0,
        )

        topo = decompose_field_topology(
            sphere_energies={"web": web},
            coupling={},
            fiber_tension={"web": 0.0},
            pearl_persistence={"web": 0.0},
            beta_1=0,
            h1_obstruction_count=0,
        )

        self.assertAlmostEqual(topo.spheres["web"].self_energy, 4.85, places=6)
        self.assertLess(topo.spheres["web"].self_energy, web.n_unknown)

    def test_world_states_from_surface_adds_domain_and_service_observations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            surface_path = Path(tmpdir) / "surface_test.json"
            surface_path.write_text(json.dumps({
                "targets": [
                    {
                        "ip": "127.0.0.1",
                        "domains": ["ai_target", "web"],
                        "services": [
                            {"port": 11434, "service": "ollama", "banner": "Ollama API (tinyllama:latest)"},
                        ],
                    },
                    {
                        "ip": "172.17.0.3",
                        "domains": ["host", "web", "data", "container_escape"],
                        "services": [
                            {"port": 22, "service": "ssh", "banner": "OpenSSH 4.7p1"},
                            {"port": 80, "service": "http", "banner": "Apache/2.2.8"},
                            {"port": 3306, "service": "mysql", "banner": "MySQL 5.0.51a"},
                        ],
                    },
                ]
            }), encoding="utf-8")

            by_sphere = _world_states_from_surface(surface_path)

        self.assertIn("ai_target", by_sphere)
        self.assertIn("web", by_sphere)
        self.assertIn("host", by_sphere)
        self.assertIn("data", by_sphere)
        self.assertIn("container", by_sphere)
        self.assertTrue(any("ollama" in s.wicket_id for s in by_sphere["ai_target"]))
        self.assertTrue(any("http" in s.wicket_id for s in by_sphere["web"]))
        self.assertTrue(any("ssh" in s.wicket_id for s in by_sphere["host"]))
        self.assertTrue(any("mysql" in s.wicket_id for s in by_sphere["data"]))

    def test_world_states_from_snapshot_adds_credentials_runtime_relations_and_access(self):
        world = {
            "identity_key": "172.17.0.3",
            "credentials": {
                "bindings": [
                    {"service": "ssh", "credentials": ["msfadmin", "/home/msfadmin/.ssh/id_rsa"]},
                ]
            },
            "datastore_access": ["MySQL accessible as root"],
            "datastore_observations": [
                {"service": "mysql", "workload_id": "mysql::172.17.0.3:3306::dvwa.users"},
            ],
            "runtime": {
                "process_count": 67,
                "process_findings": [{"wicket_id": "PI-01"}],
                "container": {"privileged": False},
                "docker_access": True,
            },
            "relations": [
                {"relation": "docker_host", "other_identity": "172.17.0.1", "strength": 0.9},
            ],
            "access_paths": [
                {"kind": "remote_access", "service": "ssh", "port": 22},
                {"kind": "datastore", "service": "mysql", "port": 3306},
                {"kind": "runtime_control", "service": "docker", "port": None},
            ],
        }

        by_sphere = _world_states_from_snapshot(world)

        self.assertIn("host", by_sphere)
        self.assertIn("data", by_sphere)
        self.assertIn("container", by_sphere)
        self.assertTrue(any("cred::ssh" in s.wicket_id for s in by_sphere["host"]))
        self.assertTrue(any("datastore_access" in s.wicket_id for s in by_sphere["data"]))
        self.assertTrue(any("runtime::PI-01" in s.wicket_id for s in by_sphere["host"]))
        self.assertTrue(any("relation::docker_host" in s.wicket_id for s in by_sphere["host"]))
        self.assertTrue(any("access::runtime_control" in s.wicket_id for s in by_sphere["container"]))

    def test_world_snapshot_fibers_capture_overlapping_world_strands(self):
        world = {
            "identity_key": "172.17.0.3",
            "credentials": {
                "bindings": [
                    {"service": "ssh", "credentials": ["msfadmin", "/home/msfadmin/.ssh/id_rsa"]},
                ]
            },
            "access_paths": [
                {"kind": "remote_access", "service": "ssh", "port": 22, "credential_candidates": ["msfadmin"]},
                {"kind": "datastore", "service": "mysql", "port": 3306, "confirmed_access": ["root access"]},
            ],
            "datastore_observations": [
                {"service": "mysql", "workload_id": "mysql::172.17.0.3:3306::dvwa.users", "detail": "rows observed"},
            ],
            "runtime": {
                "process_findings": [{"wicket_id": "PI-01"}],
                "container": {"privileged": False},
            },
            "relations": [
                {"relation": "docker_host", "other_identity": "172.17.0.1", "strength": 0.9},
            ],
        }

        fibers = _world_snapshot_fibers(world)

        self.assertTrue(any(f.kind == "credential_binding" and f.sphere == "host" for f in fibers))
        self.assertTrue(any(f.kind == "access_path" and f.sphere == "data" for f in fibers))
        self.assertTrue(any(f.kind == "datastore" and f.sphere == "data" for f in fibers))
        self.assertTrue(any(f.kind == "runtime_process" and f.sphere == "host" for f in fibers))
        self.assertTrue(any(f.kind == "container_runtime" and f.sphere == "container" for f in fibers))
        self.assertTrue(any(f.kind == "relation" and f.anchor == "docker_host" for f in fibers))

    def test_compute_field_fibers_clusters_world_strands_by_identity(self):
        target = {"ip": "172.17.0.3", "services": [], "domains": ["host", "data", "container_escape"]}
        world = {
            "identity_key": "172.17.0.3",
            "credentials": {"bindings": [{"service": "ssh", "credentials": ["msfadmin"]}]},
            "access_paths": [{"kind": "remote_access", "service": "ssh", "port": 22, "credential_candidates": ["msfadmin"]}],
            "datastore_observations": [{"service": "mysql", "workload_id": "mysql::172.17.0.3:3306::dvwa.users", "detail": "rows observed"}],
            "runtime": {"process_findings": [{"wicket_id": "PI-01"}], "container": {"privileged": False}},
            "relations": [{"relation": "docker_host", "other_identity": "172.17.0.1", "strength": 0.9}],
        }

        with mock.patch("skg.core.daemon_registry._all_targets_index", return_value=[target]), \
             mock.patch("skg.core.daemon_registry._identity_world", return_value=world), \
             mock.patch("skg.core.daemon_registry._daemon_loop_running", True):
            clusters = compute_field_fibers()

        cluster = next(c for c in clusters if c.anchor == "172.17.0.3")
        self.assertEqual(cluster.anchor, "172.17.0.3")
        self.assertIn("host", cluster.spheres)
        self.assertIn("data", cluster.spheres)
        self.assertIn("container", cluster.spheres)
        self.assertGreater(cluster.member_count, 0)
        self.assertTrue(any(f.kind == "credential_binding" for f in cluster.fibers))
        self.assertTrue(any(f.kind == "relation" for f in cluster.fibers))

    def test_pearl_states_from_ledger_add_structural_memory(self):
        from skg.topology.energy import _pearl_states_from_ledger

        with tempfile.TemporaryDirectory() as td:
            pearls = Path(td) / "pearls.jsonl"
            pearls.write_text(json.dumps({
                "id": "p1",
                "state_changes": [],
                "projection_changes": [{"kind": "domain_shift", "added": ["sysaudit"], "removed": []}],
                "reason_changes": [
                    {"instrument": "http_collector", "success": True},
                    {"instrument": "data_profiler", "success": True},
                ],
                "observation_refs": [
                    "/var/lib/skg/discovery/gravity_http_10.0.0.1_80_x.ndjson",
                    "/var/lib/skg/discovery/gravity_data_mysql_10.0.0.1:3306_x.ndjson",
                ],
                "energy_snapshot": {
                    "target_ip": "10.0.0.1",
                    "workload_id": "gravity::10.0.0.1",
                    "decay_class": "structural",
                },
                "target_snapshot": {},
                "fold_context": [],
                "timestamp": "2026-03-19T00:00:00+00:00",
            }) + "\n")

            by_sphere = _pearl_states_from_ledger(pearls)

        self.assertIn("web", by_sphere)
        self.assertIn("data", by_sphere)
        self.assertIn("host", by_sphere)
        self.assertTrue(any(ws.wicket_id == "pearl::10.0.0.1::web" for ws in by_sphere["web"]))

    def test_compute_field_energy_all_does_not_treat_pearl_memory_as_world_state(self):
        import skg.topology.energy as energy_mod

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            events_dir = tmp / "events"
            interp_dir = tmp / "interp"
            discovery_dir = tmp / "discovery"
            events_dir.mkdir()
            interp_dir.mkdir()
            discovery_dir.mkdir()
            pearls = tmp / "pearls.jsonl"
            pearls.write_text(json.dumps({
                "id": "p1",
                "state_changes": [{"wicket_id": "WB-02"}],
                "projection_changes": [],
                "reason_changes": [{"instrument": "http_collector", "success": True}],
                "observation_refs": [],
                "energy_snapshot": {
                    "target_ip": "10.0.0.1",
                    "workload_id": "host::10.0.0.1",
                    "domain": "web",
                    "decay_class": "structural",
                },
                "target_snapshot": {"workload_id": "host::10.0.0.1", "domain": "web"},
                "fold_context": [],
                "timestamp": "2026-03-27T00:00:00+00:00",
            }) + "\n", encoding="utf-8")

            with mock.patch.object(energy_mod, "DISCOVERY_DIR", discovery_dir), \
                 mock.patch.object(energy_mod, "SKG_STATE_DIR", tmp), \
                 mock.patch.object(energy_mod, "_world_states_from_runtime", return_value={}):
                energies = energy_mod.compute_field_energy_all(events_dir, interp_dir)

        self.assertEqual(energies, {})

    def test_pearl_fibers_from_ledger_capture_preserved_strands(self):
        from skg.topology.energy import _pearl_fibers_from_ledger

        with tempfile.TemporaryDirectory() as td:
            pearls = Path(td) / "pearls.jsonl"
            pearls.write_text(json.dumps({
                "id": "p2",
                "state_changes": [{"wicket_id": "WB-02"}],
                "projection_changes": [{"kind": "domain_shift", "added": ["sysaudit"], "removed": []}],
                "reason_changes": [
                    {"instrument": "http_collector", "success": True},
                    {"instrument": "sysaudit", "success": True},
                ],
                "observation_refs": [
                    "/var/lib/skg/discovery/gravity_http_10.0.0.2_80_x.ndjson",
                    "/var/lib/skg/discovery/gravity_audit_10_0_0_2_x.ndjson",
                ],
                "energy_snapshot": {
                    "target_ip": "10.0.0.2",
                    "workload_id": "gravity::10.0.0.2",
                },
                "target_snapshot": {},
                "fold_context": [{"fold_id": "f1"}],
                "timestamp": "2026-03-19T00:00:00+00:00",
            }) + "\n")

            fibers = _pearl_fibers_from_ledger(pearls)

        self.assertTrue(any(f.anchor == "10.0.0.2" for f in fibers))
        self.assertTrue(any(f.kind == "pearl_memory" for f in fibers))
        self.assertTrue(any(f.sphere == "web" for f in fibers))
        self.assertTrue(any(f.sphere == "host" for f in fibers))

    def test_fiber_coupling_matrix_derives_cross_sphere_coupling(self):
        cluster = FiberCluster(
            cluster_id="cluster::172.17.0.3",
            anchor="172.17.0.3",
            spheres=["host", "data"],
            kinds=["credential_binding", "access_path"],
            member_count=4,
            total_coherence=1.6,
            total_tension=0.2,
            fibers=[
                Fiber(
                    fiber_id="f1",
                    sphere="host",
                    kind="credential_binding",
                    anchor="ssh",
                    members=["msfadmin", "root"],
                    coherence=0.82,
                    tension=0.12,
                ),
                Fiber(
                    fiber_id="f2",
                    sphere="data",
                    kind="access_path",
                    anchor="mysql",
                    members=["root", "confirmed_access"],
                    coherence=0.88,
                    tension=0.08,
                ),
            ],
        )

        coupling = fiber_coupling_matrix([cluster])

        self.assertIn("host", coupling)
        self.assertIn("data", coupling["host"])
        self.assertGreater(coupling["host"]["data"], 0.0)
        self.assertEqual(coupling["host"]["data"], coupling["data"]["host"])

    def test_merge_coupling_matrices_adds_and_clips(self):
        merged = merge_coupling_matrices(
            {"host": {"web": 0.4}},
            {"host": {"web": 0.5}, "web": {"host": 0.5}},
            {"host": {"web": 0.4}},
        )

        self.assertEqual(merged["host"]["web"], 1.0)
        self.assertEqual(merged["web"]["host"], 0.5)

    def test_fiber_tension_by_sphere_aggregates_cluster_tension(self):
        cluster = FiberCluster(
            cluster_id="cluster::172.17.0.3",
            anchor="172.17.0.3",
            spheres=["host", "data"],
            kinds=["credential_binding", "datastore"],
            member_count=3,
            total_coherence=1.7,
            total_tension=0.22,
            fibers=[
                Fiber("f1", "host", "credential_binding", "ssh", ["msfadmin"], 0.82, 0.12),
                Fiber("f2", "data", "datastore", "mysql", ["root access"], 0.88, 0.10),
            ],
        )

        tension = fiber_tension_by_sphere([cluster])

        self.assertAlmostEqual(tension["host"], 0.113329, places=6)
        self.assertAlmostEqual(tension["data"], 0.09531, places=5)

    def test_field_topology_curvature_and_pull_include_fiber_tension(self):
        web = SphereEnergy(
            sphere="web",
            G=0.2,
            G_norm=0.3,
            n_wickets=5,
            n_realized=1,
            n_blocked=1,
            n_unknown=2,
            unknown_mass=2.5,
            total_local_energy=0.0,
            mean_local_energy=0.4,
            n_latent=0,
        )

        topo = decompose_field_topology(
            sphere_energies={"web": web},
            coupling={},
            fiber_tension={"web": 0.6},
            pearl_persistence={"web": 0.0},
            beta_1=0,
            h1_obstruction_count=0,
        )

        self.assertAlmostEqual(topo.spheres["web"].fiber_tension, 0.6, places=6)
        self.assertAlmostEqual(topo.spheres["web"].curvature, 3.2, places=6)
        self.assertGreater(topo.spheres["web"].gravity_pull, topo.spheres["web"].self_energy)

    def test_gravity_field_pull_boost_is_bounded_and_domain_aware(self):
        gravity_field = _load_gravity_field_module()
        cluster = FiberCluster(
            cluster_id="cluster::172.17.0.3",
            anchor="172.17.0.3",
            spheres=["host", "data"],
            kinds=["credential_binding", "datastore"],
            member_count=4,
            total_coherence=4.0,
            total_tension=3.0,
            fibers=[],
        )

        boost = gravity_field._bounded_field_pull_boost(
            ip="172.17.0.3",
            effective_domains={"host", "data", "container_escape"},
            sphere_pulls={"host": 12.0, "data": 8.0, "container": 6.0},
            fiber_clusters_by_anchor={"172.17.0.3": cluster},
        )

        self.assertGreater(boost, 0.0)
        self.assertLessEqual(boost, 4.0)

    def test_gravity_field_pull_boost_prefers_local_cluster_over_shared_domain_basin(self):
        gravity_field = _load_gravity_field_module()
        local_cluster = FiberCluster(
            cluster_id="cluster::172.17.0.3",
            anchor="172.17.0.3",
            spheres=["host", "data", "container"],
            kinds=["credential_binding"],
            member_count=20,
            total_coherence=10.0,
            total_tension=5.0,
            fibers=[],
        )

        local = gravity_field._bounded_field_pull_boost(
            ip="172.17.0.3",
            effective_domains={"host", "data", "container_escape", "web"},
            sphere_pulls={"host": 12.0, "data": 8.0, "container": 6.0, "web": 14.0},
            fiber_clusters_by_anchor={"172.17.0.3": local_cluster},
        )
        shared_only = gravity_field._bounded_field_pull_boost(
            ip="www.google.com",
            effective_domains={"web"},
            sphere_pulls={"host": 12.0, "data": 8.0, "container": 6.0, "web": 14.0},
            fiber_clusters_by_anchor={},
        )

        self.assertGreater(local, shared_only)

    def test_gravity_field_pull_boost_zero_when_no_matching_field_context(self):
        gravity_field = _load_gravity_field_module()

        boost = gravity_field._bounded_field_pull_boost(
            ip="172.17.0.99",
            effective_domains={"aprs"},
            sphere_pulls={},
            fiber_clusters_by_anchor={},
        )

        self.assertEqual(boost, 0.0)

    def test_anchored_field_pull_matches_gravity_boost_logic(self):
        from skg.topology.energy import anchored_field_pull

        cluster = FiberCluster(
            cluster_id="cluster::172.17.0.3",
            anchor="172.17.0.3",
            spheres=["host", "container"],
            kinds=["credential_binding", "runtime_process"],
            member_count=12,
            total_coherence=7.5,
            total_tension=4.2,
            fibers=[],
        )

        pull = anchored_field_pull(
            anchor="172.17.0.3",
            domains={"host", "container_escape", "web"},
            sphere_pulls={"host": 13.5, "container": 9.8, "web": 14.3},
            fiber_clusters_by_anchor={"172.17.0.3": cluster},
        )

        self.assertGreater(pull, 0.0)
        self.assertLessEqual(pull, 4.0)

    def test_anchored_field_pull_increases_with_pearl_persistence(self):
        from skg.topology.energy import anchored_field_pull

        cluster = FiberCluster(
            cluster_id="cluster::172.17.0.3",
            anchor="172.17.0.3",
            spheres=["web", "host"],
            kinds=["pearl_memory", "credential_binding"],
            member_count=40,
            total_coherence=18.0,
            total_tension=4.0,
            fibers=[
                Fiber(
                    fiber_id="pearl::172.17.0.3::web",
                    sphere="web",
                    kind="pearl_memory",
                    anchor="172.17.0.3",
                    members=["gravity_http", "WB-02"],
                    coherence=0.9,
                    tension=0.4,
                )
            ],
        )

        base = anchored_field_pull(
            anchor="172.17.0.3",
            domains={"web"},
            sphere_pulls={"web": 12.0},
            fiber_clusters_by_anchor={"172.17.0.3": cluster},
            sphere_persistence={"web": 0.0},
        )
        persisted = anchored_field_pull(
            anchor="172.17.0.3",
            domains={"web"},
            sphere_pulls={"web": 12.0},
            fiber_clusters_by_anchor={"172.17.0.3": cluster},
            sphere_persistence={"web": 1.2},
        )

        self.assertGreater(persisted, base)
        self.assertLessEqual(persisted, 4.0)

    def test_pearl_persistence_can_protect_a_stable_sphere(self):
        web = SphereEnergy(
            sphere="web",
            G=0.68,
            G_norm=0.68,
            n_wickets=4,
            n_realized=3,
            n_blocked=0,
            n_unknown=1,
            unknown_mass=0.8,
            total_local_energy=0.1,
            mean_local_energy=0.025,
            n_latent=0,
        )

        topo = decompose_field_topology(
            sphere_energies={"web": web},
            coupling={},
            fiber_tension={"web": 0.2},
            pearl_persistence={"web": 0.9},
            beta_1=0,
            h1_obstruction_count=0,
        )

        self.assertAlmostEqual(topo.spheres["web"].pearl_persistence, 0.9, places=6)
        self.assertTrue(topo.spheres["web"].protected_state)
        self.assertIn("persistent preserved structure", topo.spheres["web"].protected_reason)

    def test_assistant_context_builds_reasoning_bundle_with_field_and_graph_state(self):
        daemon = _load_daemon_module()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            events_dir = tmp / "events"
            interp_dir = tmp / "interp"
            state_dir = tmp / "state"
            discovery_dir = state_dir / "discovery"
            events_dir.mkdir()
            interp_dir.mkdir()
            discovery_dir.mkdir(parents=True)

            artifact = events_dir / "gravity_http_10.0.0.7_x.ndjson"
            artifact.write_text(
                json.dumps({
                    "payload": {
                        "workload_id": "host::10.0.0.7",
                        "detail": "https probe",
                    }
                }) + "\n",
                encoding="utf-8",
            )

            req = types.SimpleNamespace(
                kind="target",
                id="10.0.0.7",
                identity_key="10.0.0.7",
                limit=3,
            )
            target = {
                "ip": "10.0.0.7",
                "services": [{"port": 443, "service": "https"}],
                "os": "linux",
                "kind": "host",
                "profile": {"evidence_count": 4},
            }
            surface_rows = {
                "workloads": [{
                    "identity_key": "10.0.0.7",
                    "workload_id": "host::10.0.0.7",
                    "manifestation_key": "host::10.0.0.7",
                    "domain": "host",
                    "attack_path_id": "host_ssh_initial_access_v1",
                    "classification": "indeterminate",
                    "score": 0.82,
                    "realized": ["HO-01"],
                    "blocked": [],
                    "unknown": ["HO-02"],
                }]
            }
            field_state = {
                "host::10.0.0.7/host_ssh_initial_access_v1": {
                    "workload_id": "host::10.0.0.7",
                    "identity_key": "10.0.0.7",
                    "manifestation_key": "host::10.0.0.7",
                    "attack_path_id": "host_ssh_initial_access_v1",
                    "classification": "indeterminate",
                    "E": 0.75,
                    "E_base": 0.5,
                    "fold_contribution": 0.15,
                    "field_pull": 0.1,
                    "compatibility_score": 0.9,
                    "compatibility_span": 2,
                    "decoherence": 0.2,
                    "n_required": 4,
                    "n_realized": 2,
                    "n_blocked": 0,
                    "n_unknown": 2,
                    "unknown_nodes": ["HO-02", "HO-03"],
                    "resolution_required": {
                        "HO-02": "SSH sweep",
                        "HO-03": "HTTP probe",
                    },
                    "unresolved_reason": "Need more telemetry",
                    "computed_at": "2026-03-26T00:00:00+00:00",
                }
            }
            folds = {"folds": [{
                "fold_id": "fold-1",
                "fold_type": "structural",
                "target_ip": "10.0.0.7",
                "gravity_weight": 1.2,
                "detail": "redis service has no toolchain",
                "why": {"service": "redis", "attack_path_id": "host_ssh_initial_access_v1"},
            }]}
            proposals = {"proposals": [{
                "id": "prop-1",
                "proposal_kind": "field_action",
                "status": "pending",
                "description": "run host observation",
                "domain": "host",
                "hosts": ["10.0.0.7"],
                "confidence": 0.6,
                "fold_ids": ["fold-1"],
                "recall": {"growth_memory": {"delta": 0.02, "proposal_reasons": ["repeat pressure"]}},
                "action": {"command_hint": "skg sensors trigger"},
            }]}
            memory = {"neighborhoods": [{
                "identity_key": "10.0.0.7",
                "domain": "host",
                "pearl_count": 2,
                "mean_energy": 0.5,
                "transition_density": 0.4,
                "manifestation_keys": ["host::10.0.0.7"],
                "reinforced_wickets": ["HO-02"],
                "reinforced_reasons": ["repeat pressure"],
            }]}
            timeline = {
                "workload_count": 1,
                "snapshot_count": 2,
                "transition_count": 1,
                "transitions": [{
                    "computed_at": "2026-03-26T00:01:00+00:00",
                    "wicket_id": "HO-02",
                    "from_state": "unknown",
                    "to_state": "realized",
                    "_workload_id": "host::10.0.0.7",
                }],
                "graph_neighbors": [{"workload_id": "web::10.0.0.7:443", "weight": 0.4}],
            }
            artifacts = {"artifacts": [{
                "file": artifact.name,
                "path": str(artifact),
                "category": "events",
                "mtime": "2026-03-26T00:02:00+00:00",
                "workload_id": "host::10.0.0.7",
            }]}

            with mock.patch.object(daemon, "EVENTS_DIR", events_dir), \
                 mock.patch.object(daemon, "INTERP_DIR", interp_dir), \
                 mock.patch.object(daemon, "SKG_STATE_DIR", state_dir), \
                 mock.patch.object(daemon, "list_targets", return_value={"targets": [target]}), \
                 mock.patch.object(daemon, "field_surface", return_value=surface_rows), \
                 mock.patch.object(daemon, "folds_summary", return_value=folds), \
                 mock.patch.object(daemon, "list_proposals", return_value=proposals), \
                 mock.patch.object(daemon, "pearl_memory_manifold", return_value=memory), \
                 mock.patch.object(daemon, "_compute_field_state", return_value=field_state), \
                 mock.patch.object(daemon, "identity_timeline", return_value=timeline), \
                 mock.patch.object(daemon, "identity_artifacts", return_value=artifacts), \
                 mock.patch.object(daemon.kernel, "gravity_status", return_value={
                     "running": True,
                     "cycle": 5,
                     "current_activity": "routing",
                     "recent_output": ["candidate 10.0.0.7"],
                 }), \
                 mock.patch.object(daemon.kernel.graph, "neighbors", return_value=[
                     ("web::10.0.0.7:443", "same_identity", 0.4),
                 ]), \
                 mock.patch.object(daemon.kernel.graph, "get_prior", return_value=0.33):
                context = daemon._assistant_context(req)

        bundle = context["bundle"]
        self.assertEqual(bundle["version"], 1)
        self.assertEqual(context["field_path_count"], 1)
        self.assertEqual(bundle["field_state"]["count"], 1)
        self.assertEqual(bundle["field_state"]["paths"][0]["E"], 0.75)
        self.assertEqual(bundle["graph"]["neighbor_count"], 1)
        self.assertEqual(bundle["graph"]["priors"][0]["prior"], 0.33)
        self.assertEqual(bundle["artifacts"]["count"], 1)
        self.assertEqual(bundle["artifacts"]["items"][0]["preview"]["preview_kind"], "ndjson")
        self.assertEqual(bundle["gravity"]["cycle"], 5)

    def test_assistant_cache_key_distinguishes_selection_and_action(self):
        daemon = _load_daemon_module()
        first = {
            "kind": "target",
            "id": "10.0.0.7",
            "identity_key": "10.0.0.7",
            "task": "what_if",
            "action": {"kind": "observe"},
        }
        second = {
            "kind": "proposal",
            "id": "prop-1",
            "identity_key": "10.0.0.7",
            "task": "what_if",
            "action": {"kind": "execute"},
        }

        self.assertNotEqual(daemon._assistant_cache_key(first), daemon._assistant_cache_key(second))

    def test_assistant_what_if_fallback_uses_bundle_physics(self):
        daemon = _load_daemon_module()
        req = types.SimpleNamespace(
            kind="proposal",
            id="prop-1",
            identity_key="10.0.0.7",
            question="What if we run this?",
            action=None,
        )
        context = {
            "kind": "proposal",
            "id": "prop-1",
            "identity_key": "10.0.0.7",
            "subject": {
                "id": "prop-1",
                "kind": "field_action",
                "description": "run host observation",
                "command_hint": "skg sensors trigger",
            },
            "field_path_count": 1,
            "fold_count": 1,
            "proposal_count": 1,
            "artifacts": [{"file": "gravity_http_10.0.0.7_x.ndjson"}],
            "timeline": {"workload_count": 1, "snapshot_count": 2, "transition_count": 1},
            "assistant_config": {"enabled": False},
            "bundle": {
                "version": 1,
                "field_state": {
                    "paths": [{
                        "workload_id": "host::10.0.0.7",
                        "attack_path_id": "host_ssh_initial_access_v1",
                        "classification": "indeterminate",
                        "E": 0.75,
                        "n_unknown": 2,
                        "resolution_required": {"HO-02": "SSH sweep"},
                    }],
                },
                "folds": {"items": [{"fold_id": "fold-1"}]},
                "proposals": {"items": [{"id": "prop-1"}]},
                "graph": {
                    "neighbors": [{"workload_id": "web::10.0.0.7:443", "weight": 0.4}],
                    "priors": [{"workload_id": "host::10.0.0.7", "wicket_id": "HO-02", "prior": 0.33}],
                },
                "artifacts": {"items": [{"file": "gravity_http_10.0.0.7_x.ndjson"}]},
            },
        }

        with mock.patch.object(daemon, "_assistant_prepare_context", return_value=(context, "what_if")):
            result = daemon.assistant_what_if(req)

        self.assertEqual(result["task"], "what_if")
        self.assertEqual(result["assistant_output_class"], "derived_advice")
        self.assertEqual(result["authority"]["assistant_output_class"], "derived_advice")
        self.assertEqual(result["authority"]["state_authority"], "advisory_only")
        self.assertEqual(result["action"]["proposal_kind"], "field_action")
        self.assertTrue(result["predicted_effects"])
        self.assertTrue(any("E 0.75" in row for row in result["predicted_effects"]))
        self.assertTrue(any("counterfactual" in row.lower() for row in result["cautions"]))

    def test_assistant_explain_marks_output_as_advisory(self):
        daemon = _load_daemon_module()
        req = types.SimpleNamespace(
            kind="target",
            id="10.0.0.7",
            identity_key="10.0.0.7",
            task="target_summary",
        )
        context = {
            "kind": "target",
            "id": "10.0.0.7",
            "identity_key": "10.0.0.7",
            "subject": {"identity_key": "10.0.0.7"},
            "field_path_count": 1,
            "fold_count": 0,
            "proposal_count": 0,
            "artifacts": [],
            "timeline": {"workload_count": 1, "snapshot_count": 1, "transition_count": 0},
            "assistant_config": {"enabled": False},
            "bundle": {"version": 1, "graph": {"neighbors": []}},
        }

        with mock.patch.object(daemon, "_assistant_prepare_context", return_value=(context, "target_summary")):
            result = daemon.assistant_explain(req)

        self.assertEqual(result["assistant_output_class"], "derived_advice")
        self.assertEqual(result["authority"]["assistant_output_class"], "derived_advice")
        self.assertEqual(result["authority"]["state_authority"], "advisory_only")
        self.assertFalse(result["authority"]["observation_admissible"])

    def test_assistant_demand_derivation_prefers_physics_selected_artifacts(self):
        from skg.assistant.demands import derive_demands

        bundle = {
            "selection": {"kind": "target", "id": "10.0.0.7", "identity_key": "10.0.0.7"},
            "subject": {
                "identity_key": "10.0.0.7",
                "services": ["443/https", "22/ssh"],
                "paths": [],
            },
            "surface": {
                "identity_key": "10.0.0.7",
                "services": ["443/https", "22/ssh"],
            },
            "field_state": {
                "paths": [{
                    "workload_id": "host::10.0.0.7",
                    "attack_path_id": "host_ssh_initial_access_v1",
                    "classification": "indeterminate",
                    "E": 0.75,
                    "unknown_nodes": ["HO-02", "HO-03"],
                    "resolution_required": {"HO-02": "SSH sweep"},
                }],
            },
            "folds": {
                "items": [
                    {
                        "fold_id": "fold-struct",
                        "fold_type": "structural",
                        "gravity_weight": 1.4,
                        "detail": "redis service has no toolchain",
                        "why": {"service": "redis", "attack_path_id": "host_ssh_initial_access_v1"},
                    },
                    {
                        "fold_id": "fold-proj",
                        "fold_type": "projection",
                        "gravity_weight": 1.1,
                        "detail": "attack path implied but missing wickets",
                        "why": {"service": "https", "attack_path_id": "web_https_follow_on_v1"},
                    },
                ],
            },
            "proposals": {
                "items": [{
                    "id": "prop-1",
                    "kind": "field_action",
                    "domain": "host",
                    "description": "run host observation",
                    "command_hint": "msfconsole -r observe.rc",
                    "confidence": 0.6,
                }],
            },
        }

        demands = derive_demands(bundle, limit=6)
        kinds = [row["demand_kind"] for row in demands]

        self.assertIn("observation_rc", kinds)
        self.assertIn("wicket_patch", kinds)
        self.assertIn("catalog_patch", kinds)

    def test_assistant_writer_persists_valid_catalog_patch_draft_without_llm(self):
        from skg.assistant.writer import draft_demand
        import skg.assistant.writer as writer_module

        demand = {
            "id": "dmd_demo_catalog",
            "demand_kind": "catalog_patch",
            "contract": "catalog_patch",
            "identity_key": "10.0.0.7",
            "source": {"kind": "fold", "id": "fold-struct"},
            "title": "Draft catalog patch",
            "rationale": "Physics indicates a coverage deficit.",
            "inputs": {
                "domain": "web",
                "service_family": "redis",
                "detail": "redis service has no toolchain",
                "filename_stub": "catalog_patch_10_0_0_7_redis",
            },
        }

        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            with mock.patch.object(writer_module, "SKG_STATE_DIR", state_dir):
                result = draft_demand(demand, use_llm=False)

            saved = Path(result["path"])
            saved_exists = saved.exists()
            payload = json.loads(saved.read_text())

        self.assertTrue(saved_exists)
        self.assertEqual(result["mode"], "deterministic")
        self.assertEqual(payload["patch_type"], "catalog_patch_v1")
        self.assertEqual(payload["domain"], "web")

    def test_assistant_validator_rejects_invalid_catalog_patch_shape(self):
        from skg.assistant.validators import get_contract, validate_draft

        result = validate_draft(
            {"contract": "catalog_patch"},
            {
                "filename_hint": "bad.json",
                "content": {
                    "patch_type": "catalog_patch_v1",
                    "domain": "host",
                    "description": "draft",
                    "reason": "physics",
                    "wickets": [],
                    "attack_paths": "not-a-mapping",
                },
                "notes": ["review"],
            },
            get_contract("catalog_patch"),
        )

        self.assertFalse(result["ok"])
        self.assertTrue(any("wickets" in err for err in result["errors"]))
        self.assertTrue(any("attack_paths" in err for err in result["errors"]))

    def test_contract_backed_msf_action_proposal_writes_artifact_and_metadata(self):
        import skg.assistant.action_proposals as proposal_module

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)

            def _fake_create_action(**kwargs):
                return {"id": "prop-msf-1", **kwargs}

            with mock.patch.object(proposal_module, "create_action", side_effect=_fake_create_action):
                proposal, artifact = proposal_module.create_msf_action_proposal(
                    contract_name="msf_rc",
                    rc_text="use auxiliary/scanner/http/http_version\nexit\n",
                    filename_hint="demo.rc",
                    out_dir=out_dir,
                    domain="web",
                    description="demo",
                    attack_surface="10.0.0.7:80",
                    hosts=["10.0.0.7"],
                    category="runtime_observation",
                    evidence="demo evidence",
                    action={"instrument": "msf", "target_ip": "10.0.0.7", "port": 80},
                )

            self.assertEqual(proposal["action"]["artifact_contract"], "msf_rc")
            self.assertEqual(proposal["action"]["rc_file"], artifact["path"])
            self.assertEqual(proposal["action"]["identity_key"], "10.0.0.7")
            self.assertEqual(proposal["action"]["execution_target"], "10.0.0.7")
            self.assertTrue(Path(artifact["path"]).exists())
            self.assertTrue(Path(artifact["meta_path"]).exists())

    def test_daemon_assistant_demands_and_draft_endpoint(self):
        daemon = _load_daemon_module()
        import skg.assistant.writer as writer_module

        context = {
            "identity_key": "10.0.0.7",
            "field_path_count": 1,
            "fold_count": 2,
            "proposal_count": 1,
            "artifacts": [],
            "bundle": {
                "version": 1,
                "selection": {"kind": "target", "id": "10.0.0.7", "identity_key": "10.0.0.7"},
                "subject": {"identity_key": "10.0.0.7"},
                "surface": {"services": ["443/https"]},
                "field_state": {
                    "paths": [{
                        "workload_id": "host::10.0.0.7",
                        "attack_path_id": "host_ssh_initial_access_v1",
                        "classification": "indeterminate",
                        "E": 0.75,
                        "unknown_nodes": ["HO-02"],
                        "resolution_required": {"HO-02": "SSH sweep"},
                    }],
                },
                "folds": {
                    "items": [{
                        "fold_id": "fold-struct",
                        "fold_type": "structural",
                        "gravity_weight": 1.4,
                        "detail": "redis service has no toolchain",
                        "why": {"service": "redis", "attack_path_id": "host_ssh_initial_access_v1"},
                    }],
                },
                "proposals": {
                    "items": [{
                        "id": "prop-1",
                        "kind": "field_action",
                        "domain": "host",
                        "description": "run host observation",
                        "command_hint": "msfconsole -r observe.rc",
                        "confidence": 0.6,
                    }],
                },
            },
        }

        req = types.SimpleNamespace(
            kind="target",
            id="10.0.0.7",
            identity_key="10.0.0.7",
            limit=6,
            context=None,
            demand=None,
            demand_id="",
            demand_kind="catalog_patch",
            use_llm=False,
        )

        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            with mock.patch.object(daemon, "_assistant_bundle_context", return_value=context), \
                 mock.patch.object(writer_module, "SKG_STATE_DIR", state_dir):
                listed = daemon.assistant_demands(req)
                drafted = daemon.assistant_draft_demand(req)
                drafted_exists = Path(drafted["draft"]["path"]).exists()

        self.assertGreaterEqual(listed["count"], 2)
        self.assertEqual(listed["assistant_output_class"], "derived_advice")
        self.assertEqual(listed["authority"]["assistant_output_class"], "derived_advice")
        self.assertEqual(listed["authority"]["state_authority"], "advisory_only")
        self.assertEqual(drafted["assistant_output_class"], "mutation_artifact")
        self.assertEqual(drafted["authority"]["assistant_output_class"], "mutation_artifact")
        self.assertEqual(drafted["authority"]["state_authority"], "advisory_only")
        self.assertEqual(drafted["draft"]["demand"]["demand_kind"], "catalog_patch")
        self.assertEqual(drafted["draft"]["assistant_output_class"], "mutation_artifact")
        self.assertEqual(drafted["draft"]["authority"]["assistant_output_class"], "mutation_artifact")
        self.assertTrue(drafted_exists)

    def test_daemon_assistant_draft_uses_derived_demand_not_inline_payload(self):
        daemon = _load_daemon_module()
        import skg.assistant.writer as writer_module

        context = {
            "identity_key": "10.0.0.7",
            "field_path_count": 0,
            "fold_count": 1,
            "proposal_count": 0,
            "artifacts": [],
            "bundle": {
                "version": 1,
                "selection": {"kind": "target", "id": "10.0.0.7", "identity_key": "10.0.0.7"},
                "subject": {"identity_key": "10.0.0.7"},
                "surface": {"services": ["443/https"]},
                "field_state": {"paths": []},
                "folds": {
                    "items": [{
                        "fold_id": "fold-struct",
                        "fold_type": "structural",
                        "gravity_weight": 1.4,
                        "detail": "redis service has no toolchain",
                        "why": {"service": "redis", "attack_path_id": "host_ssh_initial_access_v1"},
                    }],
                },
                "proposals": {"items": []},
            },
        }

        req = types.SimpleNamespace(
            kind="target",
            id="10.0.0.7",
            identity_key="10.0.0.7",
            limit=6,
            context=None,
            demand={
                "id": "manual-inline",
                "demand_kind": "catalog_patch",
                "contract": "catalog_patch",
                "identity_key": "10.0.0.7",
                "source": {"kind": "manual", "id": "caller"},
                "title": "manual",
                "rationale": "manual",
                "inputs": {"domain": "manual", "filename_stub": "manual"},
                "selection": {"kind": "target", "id": "10.0.0.7", "identity_key": "10.0.0.7"},
            },
            demand_id="",
            demand_kind="",
            use_llm=False,
        )

        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            with mock.patch.object(daemon, "_assistant_bundle_context", return_value=context), \
                 mock.patch.object(writer_module, "SKG_STATE_DIR", state_dir):
                drafted = daemon.assistant_draft_demand(req)

        self.assertEqual(drafted["assistant_output_class"], "mutation_artifact")
        self.assertEqual(drafted["draft"]["demand"]["source"]["kind"], "fold")
        self.assertEqual(drafted["draft"]["demand"]["source"]["id"], "fold-struct")

    def test_msf_sensor_resolves_only_requested_targets(self):
        from skg.sensors import msf_sensor as msf_sensor_module

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_dir = Path(tmpdir) / "cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "targets.yaml").write_text(
                "\n".join([
                    "targets:",
                    "  - host: 10.0.0.7",
                    "    workload_id: host::10.0.0.7",
                    "  - host: 10.0.0.8",
                    "    workload_id: host::10.0.0.8",
                ]),
                encoding="utf-8",
            )

            with mock.patch.object(msf_sensor_module, "SKG_CONFIG_DIR", cfg_dir), \
                 mock.patch.object(msf_sensor_module, "SKG_HOME", Path(tmpdir)):
                sensor = msf_sensor_module.MsfSensor({"password": "x"})
                targets = sensor._resolve_targets(["host::10.0.0.7"])

        self.assertEqual(targets, ["10.0.0.7"])

    def test_exploit_dispatch_uses_contract_backed_proposal_helper(self):
        exploit_dispatch = _load_exploit_dispatch_module()

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            fake_proposal = {"id": "prop-1"}
            fake_artifact = {"path": str(out_dir / "demo.rc"), "meta_path": str(out_dir / "demo.rc.meta.json")}
            with mock.patch.object(
                exploit_dispatch,
                "EXPLOIT_MAP",
                {
                    "demo_path": [{
                        "module": "exploit/test/demo",
                        "requires": ["HO-01"],
                        "options": {"RHOSTS": "{target_ip}", "RPORT": "{port}"},
                        "confidence": 0.7,
                    }]
                },
            ), mock.patch.object(
                exploit_dispatch,
                "create_msf_action_proposal",
                return_value=(fake_proposal, fake_artifact),
            ) as helper, mock.patch.object(
                exploit_dispatch,
                "interactive_review",
                return_value={"decision": "deferred"},
            ):
                proposals = exploit_dispatch.generate_exploit_proposals(
                    path_id="demo_path",
                    target_ip="10.0.0.7",
                    port=80,
                    realized_wickets=["HO-01"],
                    out_dir=out_dir,
                )

        self.assertEqual(proposals, [fake_proposal])
        self.assertEqual(helper.call_count, 1)
        self.assertEqual(helper.call_args.kwargs["contract_name"], "msf_rc")
        self.assertEqual(helper.call_args.kwargs["action"]["identity_key"], "10.0.0.7")
        self.assertEqual(helper.call_args.kwargs["action"]["execution_target"], "10.0.0.7")

    def test_cred_reuse_uses_contract_backed_action_proposal(self):
        cred_reuse = _load_cred_reuse_module()
        import skg.assistant.action_proposals as proposal_module

        captured = {}

        def _fake_create_action_proposal(**kwargs):
            captured.update(kwargs)
            return {"id": "prop-cred-1"}, {"path": "/tmp/cred_reuse_demo.json"}

        with mock.patch.object(
            proposal_module,
            "create_action_proposal",
            side_effect=_fake_create_action_proposal,
        ) as helper:
            cred_reuse._emit_cred_proposal(
                target_ip="10.0.0.8",
                port=22,
                user="alice",
                secret="s3cr3t",
                cred_type="password",
                origin_ip="10.0.0.7",
                service_type="ssh",
            )

        self.assertEqual(helper.call_count, 1)
        self.assertEqual(captured["contract_name"], "credential_test_plan")
        self.assertEqual(captured["action"]["instrument"], "ssh")
        self.assertEqual(captured["action"]["identity_key"], "10.0.0.8")
        self.assertEqual(captured["action"]["execution_target"], "10.0.0.8")
        self.assertEqual(captured["action"]["dispatch"]["kind"], "cred_reuse")
        self.assertEqual(captured["artifact_content"]["plan_type"], "cred_reuse_v1")
        self.assertEqual(captured["artifact_content"]["identity_key"], "10.0.0.8")
        self.assertEqual(captured["artifact_content"]["target_ip"], "10.0.0.8")
        self.assertIn("--service ssh", captured["artifact_content"]["command_hint"])

    def test_list_targets_includes_measured_only_identity(self):
        daemon = _load_daemon_module()
        measured_surface = {
            "workloads": [{
                "identity_key": "db.internal",
                "workload_id": "mysql::db.internal:3306::users",
                "manifestation_key": "mysql::db.internal:3306::users",
                "domain": "data",
                "realized": ["DP-02"],
                "blocked": [],
                "unknown": ["DP-01"],
                "observed_tools": {
                    "tool_names": ["checksec", "nikto"],
                    "observed_tools": [
                        {"name": "checksec", "instrument_names": ["binary_analysis"], "domain_hints": ["binary"]},
                        {"name": "nikto", "instrument_names": ["nikto"], "domain_hints": ["web"]},
                    ],
                    "domain_hints": ["binary", "web"],
                    "instrument_hints": ["binary_analysis", "nikto"],
                    "scope": "node_local",
                    "status": "realized",
                },
            }],
            "view_nodes": [],
        }

        with mock.patch.object(daemon, "_all_targets_index", return_value=[{
            "ip": "10.0.0.7",
            "services": [{"port": 22, "service": "ssh"}],
            "domains": ["host"],
            "kind": "linux",
        }]), mock.patch.object(
            daemon,
            "field_surface",
            return_value=measured_surface,
        ), mock.patch.object(
            daemon,
            "_identity_profile",
            return_value={"evidence_count": 1},
        ), mock.patch.object(
            daemon,
            "_identity_world",
            return_value={"world_summary": {"service_count": 1}},
        ), mock.patch.object(
            daemon,
            "_identity_relations",
            return_value=[],
        ):
            result = daemon.list_targets()

        rows = {row["identity_key"]: row for row in result["targets"]}
        self.assertIn("db.internal", rows)
        self.assertEqual(rows["db.internal"]["fresh_unknown_mass"], 1)
        self.assertIn("data", rows["db.internal"]["domains"])
        self.assertEqual(rows["db.internal"]["observed_tools"]["tool_names"], ["checksec", "nikto"])
        self.assertIn("10.0.0.7", rows)

    def test_assistant_compact_fold_exposes_identity_key(self):
        daemon = _load_daemon_module()
        compact = daemon._assistant_compact_fold({
            "fold_id": "fold-1",
            "fold_type": "structural",
            "location": "mysql::db.internal:3306::users",
            "detail": "mysql surface mismatch",
            "why": {"service": "mysql", "attack_path_id": "data_exposure_v1"},
        })

        self.assertEqual(compact["identity_key"], "db.internal")

    def test_fold_resolve_accepts_identity_key(self):
        daemon = _load_daemon_module()
        from skg.kernel.folds import Fold, FoldManager

        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir)
            folds_dir = state_dir / "discovery" / "folds"
            folds_dir.mkdir(parents=True, exist_ok=True)

            fm = FoldManager()
            fm.add(Fold(
                fold_type="structural",
                location="mysql::db.internal:3306::users",
                constraint_source="gap_detector::mysql",
                detail="mysql fold",
            ))
            fold_id = fm.all()[0].id
            fold_file = folds_dir / "folds_db.internal.json"
            fm.persist(fold_file)

            recorded = []

            class _FakeLedger:
                def __init__(self, *_args, **_kwargs):
                    pass

                def record(self, pearl):
                    recorded.append(pearl)

            with mock.patch.object(daemon, "SKG_STATE_DIR", state_dir), \
                 mock.patch.object(daemon, "PearlLedger", _FakeLedger):
                result = daemon.fold_resolve(fold_id[:8], identity_key="db.internal")

            remaining = FoldManager.load(fold_file)

        self.assertTrue(result["ok"])
        self.assertEqual(result["identity_key"], "db.internal")
        self.assertEqual(len(remaining.all()), 0)
        self.assertEqual(recorded[0].energy_snapshot["identity_key"], "db.internal")

    def test_cred_store_uses_identity_aliases_for_test_tracking(self):
        cred_reuse = _load_cred_reuse_module()

        with tempfile.TemporaryDirectory() as td:
            store = cred_reuse.CredentialStore(Path(td) / "credentials.jsonl")
            record = store.add("alice", "s3cr3t", "db.internal", origin_wicket="WB-08")

            self.assertEqual(store.untested_for("mysql::db.internal:3306::users"), [])

            store.mark_tested(record["id"], "mysql::db.internal:3306::users")
            persisted = store.all()[0]

        self.assertEqual(persisted["origin_identity"], "db.internal")
        self.assertEqual(persisted["tested_on"], ["db.internal"])

    def test_cred_reuse_extracts_identity_from_workload_when_target_ip_missing(self):
        cred_reuse = _load_cred_reuse_module()

        with tempfile.TemporaryDirectory() as td:
            events_dir = Path(td) / "events"
            events_dir.mkdir(parents=True, exist_ok=True)
            (events_dir / "cred.ndjson").write_text(
                json.dumps({
                    "type": "obs.attack.precondition",
                    "payload": {
                        "wicket_id": "WB-08",
                        "status": "realized",
                        "workload_id": "mysql::db.internal:3306::users",
                        "detail": "Creds accepted: alice:s3cr3t",
                    },
                }) + "\n",
                encoding="utf-8",
            )
            store = cred_reuse.CredentialStore(Path(td) / "credentials.jsonl")
            added = cred_reuse.extract_from_events(events_dir, store)

        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["origin_ip"], "db.internal")
        self.assertEqual(added[0]["origin_identity"], "db.internal")

    def test_daemon_gravity_run_accepts_identity_key(self):
        daemon = _load_daemon_module()

        with mock.patch.object(daemon.kernel, "gravity_run_target") as runner, \
             mock.patch.object(daemon.kernel, "gravity_status", return_value={"running": True}):
            result = daemon.gravity_run(identity_key="db.internal")

        runner.assert_called_once_with("db.internal", authorized=False)
        self.assertEqual(result["identity_key"], "db.internal")
        self.assertEqual(result["target_ip"], "")


if __name__ == "__main__":
    unittest.main()
