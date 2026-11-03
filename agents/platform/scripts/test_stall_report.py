#!/usr/bin/env python3
"""Unit tests for stall_report.py: fixture objects, kubectl stubbed."""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
import stall_report  # noqa: E402

NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
NAMESPACE = "payments"


def stamp(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def managed(minutes_ago: float, field: str = "f:spec", operation: str = "Update") -> dict:
    return {"operation": operation, "time": stamp(minutes_ago), "fieldsV1": {field: {}}}


def obj(kind: str, name: str, spec=None, status=None, created_minutes_ago=120, managed_fields=None):
    meta = {
        "name": name,
        "namespace": NAMESPACE,
        "generation": 1,
        "creationTimestamp": stamp(created_minutes_ago),
    }
    if managed_fields is not None:
        meta["managedFields"] = managed_fields
    out = {"kind": kind, "metadata": meta}
    if spec is not None:
        out["spec"] = spec
    if status is not None:
        out["status"] = status
    return out


def condition(ctype: str, status: str, minutes_ago: float, reason: str = "") -> dict:
    return {"type": ctype, "status": status, "lastTransitionTime": stamp(minutes_ago), "reason": reason}


def warning(kind: str, name: str, count: int, first_ago: float, last_ago: float, reason="SYNC") -> dict:
    return {
        "type": "Warning",
        "reason": reason,
        "message": "error  processing   listener",
        "count": count,
        "firstTimestamp": stamp(first_ago),
        "lastTimestamp": stamp(last_ago),
        "involvedObject": {"kind": kind, "name": name, "namespace": NAMESPACE},
    }


class FakeResolver(stall_report.NameResolver):
    """A resolver over an in-memory namespace: {(resource, namespace): names}."""

    def __init__(self, existing: dict):
        super().__init__(lister=lambda resource, ns: existing.get((resource, ns)))
        self.existing = existing


class FakeReader:
    """Answers the scaled-to-zero reads from {args tuple: listing}; anything
    else reads as an empty list. `calls` records every read."""

    def __init__(self, listings=None):
        self.listings = listings or {}
        self.calls = []

    def __call__(self, args):
        self.calls.append(tuple(args))
        listing = self.listings.get(tuple(args), {"items": []})
        if isinstance(listing, Exception):
            raise listing
        return listing


def analyze(objects, events=(), existing=None, override=None, listings=None):
    resolver = FakeResolver(existing or {})
    scale = stall_report.ScaleResolver(reader=FakeReader(listings))
    return stall_report.analyze(list(objects), list(events), resolver, NOW, override, scale)


def healthy_deployment(name="web") -> dict:
    return obj(
        "Deployment",
        name,
        spec={"replicas": 2, "template": {"spec": {"containers": [{"name": "app", "image": "x"}]}}},
        status={
            "observedGeneration": 1,
            "conditions": [
                condition("Available", "True", 300, "MinimumReplicasAvailable"),
                condition("Progressing", "True", 300, "NewReplicaSetAvailable"),
            ],
        },
        managed_fields=[managed(300), managed(299, "f:status")],
    )


class GenerationLag(unittest.TestCase):
    def test_lag_past_threshold_is_reported(self):
        cr = obj("CertificateRequest", "api-cert", spec={}, status={"observedGeneration": 2})
        cr["metadata"]["generation"] = 3
        cr["metadata"]["managedFields"] = [managed(40), managed(1, "f:status")]
        rows = analyze([cr])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["heuristic"], "generation-lag")
        self.assertEqual(rows[0]["object"], "CertificateRequest/api-cert")
        self.assertIn("generation 3, observedGeneration 2", rows[0]["detail"])
        self.assertEqual(rows[0]["stalled_for"], "40m")

    def test_lag_under_threshold_is_not_reported(self):
        cr = obj("CertificateRequest", "api-cert", spec={}, status={"observedGeneration": 2})
        cr["metadata"]["generation"] = 3
        cr["metadata"]["managedFields"] = [managed(5)]
        self.assertEqual(analyze([cr]), [])

    def test_status_write_does_not_reset_the_age(self):
        cr = obj("Thing", "t", spec={}, status={"observedGeneration": 1}, managed_fields=[managed(50), managed(1, "f:status")])
        cr["metadata"]["generation"] = 2
        rows = analyze([cr])
        self.assertEqual(rows[0]["stalled_for"], "50m")

    def test_no_observed_generation_is_skipped(self):
        svc = obj("Service", "svc", spec={"ports": []}, status={"loadBalancer": {}})
        svc["metadata"]["generation"] = 4
        self.assertEqual(analyze([svc]), [])

    def test_deployment_uses_its_shorter_horizon(self):
        dep = healthy_deployment()
        dep["metadata"]["generation"] = 2
        dep["metadata"]["managedFields"] = [managed(12)]
        rows = analyze([dep])
        self.assertEqual([r["heuristic"] for r in rows], ["generation-lag"])
        self.assertEqual(analyze([dep], override=15), [])


class StaleConditions(unittest.TestCase):
    def test_stale_false_condition_is_reported(self):
        dep = healthy_deployment()
        dep["status"]["conditions"] = [
            condition("Available", "False", 30, "MinimumReplicasUnavailable"),
            condition("Progressing", "False", 30, "ProgressDeadlineExceeded"),
        ]
        rows = analyze([dep])
        self.assertEqual({r["heuristic"] for r in rows}, {"stale-condition"})
        self.assertEqual(len(rows), 2)
        self.assertIn("Progressing=False ProgressDeadlineExceeded", [r["detail"] for r in rows])

    def test_fresh_false_condition_is_not_reported(self):
        dep = healthy_deployment()
        dep["status"]["conditions"] = [condition("Progressing", "True", 2, "ReplicaSetUpdated"), condition("Available", "False", 2)]
        self.assertEqual(analyze([dep]), [])

    def test_unrelated_condition_types_are_ignored(self):
        hpa = obj("HorizontalPodAutoscaler", "web", status={"conditions": [condition("ScalingLimited", "False", 500)]})
        self.assertEqual(analyze([hpa]), [])

    def test_nested_listener_condition_names_the_listener(self):
        gw = obj(
            "Gateway",
            "edge",
            spec={"listeners": [{"name": "https", "tls": {"certificateRefs": [{"name": "edge-tls"}]}}]},
            status={
                "conditions": [condition("Accepted", "True", 100), condition("Programmed", "True", 100)],
                "listeners": [
                    {
                        "name": "https",
                        "conditions": [condition("ResolvedRefs", "False", 90, "InvalidCertificateRef")],
                    }
                ],
            },
            managed_fields=[managed(100)],
        )
        rows = analyze([gw], existing={("secrets", NAMESPACE): {"other"}})
        details = {r["heuristic"]: r["detail"] for r in rows}
        self.assertEqual(details["stale-condition"], "listeners[https] ResolvedRefs=False InvalidCertificateRef")

    def test_epoch_transition_time_is_clamped_to_creation(self):
        gw = obj("Gateway", "edge", spec={}, status={"conditions": [
            {"type": "Accepted", "status": "Unknown", "reason": "Pending", "lastTransitionTime": "1970-01-01T00:00:00Z"},
        ]}, created_minutes_ago=5)
        self.assertEqual(analyze([gw]), [])
        gw["metadata"]["creationTimestamp"] = stamp(40)
        rows = analyze([gw])
        self.assertEqual([r["stalled_for"] for r in rows], ["40m"])

    def test_finished_pod_is_skipped_by_every_heuristic(self):
        for phase in ("Succeeded", "Failed"):
            pod = obj(
                "Pod",
                "job-x",
                spec={"volumes": [{"name": "cfg", "configMap": {"name": "gone"}}]},
                status={"phase": phase, "observedGeneration": 0, "conditions": [condition("Ready", "False", 900, "PodCompleted")]},
                managed_fields=[managed(900)],
            )
            pod["metadata"]["generation"] = 1
            events = [warning("Pod", "job-x", 9, first_ago=800, last_ago=1)]
            self.assertEqual(analyze([pod], events=events, existing={("configmaps", NAMESPACE): set()}), [], phase)

    def test_retired_replicaset_is_skipped_by_every_heuristic(self):
        rs = obj(
            "ReplicaSet",
            "web-old",
            spec={"replicas": 0, "template": {"spec": {"containers": [{"name": "app", "envFrom": [{"configMapRef": {"name": "web-config-abc123"}}]}]}}},
            status={"observedGeneration": 1, "replicas": 0, "conditions": [condition("Ready", "False", 900)]},
            managed_fields=[managed(900)],
        )
        rs["metadata"]["generation"] = 2
        events = [warning("ReplicaSet", "web-old", 9, first_ago=800, last_ago=1)]
        existing = {("configmaps", NAMESPACE): set()}
        self.assertEqual(analyze([rs], events=events, existing=existing), [])
        rs["spec"]["replicas"] = 1
        rows = analyze([rs], events=events, existing=existing)
        self.assertIn("dangling-reference", [r["heuristic"] for r in rows])

    def test_finished_job_is_skipped_by_every_heuristic(self):
        def job(conditions):
            j = obj(
                "Job",
                "backup-1",
                spec={"template": {"spec": {"containers": [{"name": "app", "envFrom": [{"secretRef": {"name": "backup-creds"}}]}]}}},
                status={"observedGeneration": 0, "conditions": conditions},
                managed_fields=[managed(900)],
            )
            j["metadata"]["generation"] = 1
            return j

        events = [warning("Job", "backup-1", 9, first_ago=800, last_ago=1)]
        existing = {("secrets", NAMESPACE): set()}
        for ctype in ("Complete", "Failed"):
            finished = job([condition("Ready", "False", 900), condition(ctype, "True", 850)])
            self.assertEqual(analyze([finished], events=events, existing=existing), [], ctype)
        running = job([condition("Complete", "False", 850)])
        rows = analyze([running], events=events, existing=existing)
        self.assertIn("dangling-reference", [r["heuristic"] for r in rows])

    def test_paused_deployment_is_not_a_stall(self):
        dep = healthy_deployment()
        dep["spec"]["paused"] = True
        dep["status"]["conditions"] = [condition("Progressing", "Unknown", 600, "DeploymentPaused")]
        self.assertEqual(analyze([dep]), [])

    def test_route_parent_condition_names_the_gateway(self):
        route = obj(
            "HTTPRoute",
            "web",
            spec={},
            status={"parents": [
                {"parentRef": {"name": "edge"}, "conditions": [condition("Accepted", "True", 100)]},
                {"parentRef": {"name": "shared", "namespace": "infra"}, "conditions": [condition("Accepted", "False", 100, "NotAllowedByListeners")]},
            ]},
        )
        rows = analyze([route])
        self.assertEqual([r["detail"] for r in rows], ["parents[shared] Accepted=False NotAllowedByListeners"])


def workload(kind, name, replicas, labels, namespace=NAMESPACE):
    return {"kind": kind, "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {"replicas": replicas, "template": {"metadata": {"labels": labels}}}}


def off_gateway(name="edge", class_name="eg", listener_programmed="True"):
    return obj(
        "Gateway",
        name,
        spec={"gatewayClassName": class_name, "listeners": [{"name": "http"}]},
        status={
            "conditions": [condition("Accepted", "True", 600), condition("Programmed", "False", 600, "NoResources")],
            "listeners": [{"name": "http", "attachedRoutes": 1, "conditions": [condition("Programmed", listener_programmed, 600, "Invalid")]}],
        },
        managed_fields=[managed(600)],
    )


ENVOY = "gateway.envoyproxy.io/gatewayclass-controller"
ENVOY_SELECTOR = f"gateway.envoyproxy.io/owning-gateway-name=edge,gateway.envoyproxy.io/owning-gateway-namespace={NAMESPACE}"


def gateway_class(name, controller):
    return {("get", "gatewayclasses.gateway.networking.k8s.io", name): {"kind": "GatewayClass", "metadata": {"name": name}, "spec": {"controllerName": controller}}}


def envoy_proxy(replicas, namespace="envoy-gateway-system"):
    """Envoy Gateway's proxy for Gateway edge, in its controller namespace;
    the Gateway's own namespace holds none."""
    return {
        ("get", "deployments", "-l", ENVOY_SELECTOR, "-n", namespace): {"items": [workload("Deployment", f"envoy-{NAMESPACE}-edge-abc", replicas, {}, namespace=namespace)]},
    }


class ScaledToZero(unittest.TestCase):
    """A Gateway whose in-cluster proxy is scaled to zero on purpose."""

    def test_the_programmed_row_goes_when_the_envoy_proxy_is_at_zero(self):
        listings = {**gateway_class("eg", ENVOY), **envoy_proxy(0)}
        self.assertEqual(analyze([off_gateway()], listings=listings), [])

    def test_the_programmed_row_stays_when_the_envoy_proxy_runs(self):
        listings = {**gateway_class("eg", ENVOY), **envoy_proxy(1)}
        rows = analyze([off_gateway()], listings=listings)
        self.assertEqual([r["detail"] for r in rows], ["Programmed=False NoResources"])

    def test_every_other_row_of_the_gateway_stays(self):
        # A listener that is not programmed, and a missing certificate, are
        # not what a scale to zero causes.
        gateway = off_gateway(listener_programmed="False")
        gateway["spec"]["listeners"][0]["tls"] = {"certificateRefs": [{"name": "edge-tls"}]}
        listings = {**gateway_class("eg", ENVOY), **envoy_proxy(0)}
        rows = analyze([gateway], existing={("secrets", NAMESPACE): set()}, listings=listings)
        self.assertEqual(
            sorted(r["detail"] for r in rows),
            ["listeners[0].tls.certificateRefs -> Secret/edge-tls not found", "listeners[http] Programmed=False Invalid"],
        )

    def test_another_controllers_proxy_is_found_by_the_standard_label_in_the_gateways_namespace(self):
        listings = {
            **gateway_class("istio", "istio.io/gateway-controller"),
            ("get", "deployments", "-l", "gateway.networking.k8s.io/gateway-name=edge", "-n", NAMESPACE): {"items": [workload("Deployment", "edge-istio", 0, {})]},
        }
        self.assertEqual(analyze([off_gateway(class_name="istio")], listings=listings), [])

    def test_a_zero_replica_deployment_in_another_namespace_does_not_silence_the_gateway(self):
        # Only the Gateway's namespace and Envoy Gateway's controller
        # namespace are read; a look-alike planted elsewhere is never seen.
        reader = FakeReader({**gateway_class("eg", ENVOY), **envoy_proxy(0, namespace="tenant-b")})
        rows = stall_report.analyze([off_gateway()], [], FakeResolver({}), NOW, None, stall_report.ScaleResolver(reader=reader))
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            sorted(c for c in reader.calls if c[1] == "deployments"),
            [("get", "deployments", "-l", ENVOY_SELECTOR, "-n", "envoy-gateway-system"), ("get", "deployments", "-l", ENVOY_SELECTOR, "-n", NAMESPACE)],
        )

    def test_a_gateway_with_no_in_cluster_proxy_keeps_the_row(self):
        # GKE's managed classes run no proxy Deployment, so none is found.
        listings = gateway_class("gke-l7-rilb", "networking.gke.io/gateway")
        self.assertEqual(len(analyze([off_gateway(class_name="gke-l7-rilb")], listings=listings)), 1)

    def test_a_failed_read_keeps_the_row(self):
        listings = {**gateway_class("eg", ENVOY), ("get", "deployments", "-l", ENVOY_SELECTOR, "-n", NAMESPACE): RuntimeError("forbidden"), **envoy_proxy(0)}
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(len(analyze([off_gateway()], listings=listings)), 1)
        self.assertIn("scaled-to-zero check could not read", err.getvalue())

    def test_a_route_is_left_alone(self):
        route = obj(
            "HTTPRoute",
            "web",
            spec={"parentRefs": [{"name": "edge", "sectionName": "htps"}], "rules": [{"backendRefs": [{"name": "web", "port": 80}]}]},
            status={"parents": [{"parentRef": {"name": "edge"}, "conditions": [condition("Accepted", "False", 600, "NoMatchingParent")]}]},
        )
        reader = FakeReader({**gateway_class("eg", ENVOY), **envoy_proxy(0)})
        rows = stall_report.analyze([route], [], FakeResolver({}), NOW, None, stall_report.ScaleResolver(reader=reader))
        self.assertEqual([r["detail"] for r in rows], ["parents[edge] Accepted=False NoMatchingParent"])
        self.assertEqual(reader.calls, [])

    def test_a_healthy_gateway_costs_no_read(self):
        gateway = off_gateway()
        gateway["status"]["conditions"][1] = condition("Programmed", "True", 600)
        reader = FakeReader()
        rows = stall_report.analyze([gateway, healthy_deployment()], [], FakeResolver({}), NOW, None, stall_report.ScaleResolver(reader=reader))
        self.assertEqual((rows, reader.calls), ([], []))

    def test_a_workload_scaled_to_zero_leaves_no_scheduling_rows(self):
        # Its Pods are deleted, so their FailedScheduling events name no
        # object in the scan and are not reported.
        dep = healthy_deployment()
        dep["spec"]["replicas"] = 0
        events = [warning("Pod", "web-abc-123", 9, first_ago=60, last_ago=1, reason="FailedScheduling")]
        self.assertEqual(analyze([dep], events=events), [])


class RepeatingWarnings(unittest.TestCase):
    def test_rising_count_over_the_threshold_is_reported(self):
        gw = obj("Gateway", "edge", spec={}, status={})
        rows = analyze([gw], events=[warning("Gateway", "edge", 27, first_ago=40, last_ago=1)])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["heuristic"], "repeating-warnings")
        self.assertEqual(rows[0]["detail"], "SYNC x27: error processing listener")
        self.assertEqual(rows[0]["stalled_for"], "39m")

    def test_single_or_short_or_stale_warnings_are_not_reported(self):
        gw = obj("Gateway", "edge", spec={}, status={})
        once = warning("Gateway", "edge", 1, first_ago=40, last_ago=40)
        brief = warning("Gateway", "edge", 5, first_ago=5, last_ago=1)
        long_ago = warning("Gateway", "edge", 30, first_ago=400, last_ago=200)
        normal = dict(warning("Gateway", "edge", 30, first_ago=40, last_ago=1), type="Normal")
        self.assertEqual(analyze([gw], events=[once, brief, long_ago, normal]), [])

    def test_events_on_other_objects_do_not_attach(self):
        gw = obj("Gateway", "edge", spec={}, status={})
        self.assertEqual(analyze([gw], events=[warning("Gateway", "other", 27, 40, 1)]), [])

    def test_long_sync_message_keeps_the_secret_name(self):
        # The GKE Gateway controller's SYNC event names the missing Secret last,
        # and on the default read-only identity this row is what names it.
        gw = obj("Gateway", "checkout-gateway", spec={}, status={})
        event = warning("Gateway", "checkout-gateway", 4, first_ago=40, last_ago=1)
        event["message"] = (
            'failed to translate Gateway "seeded-reliability/checkout-gateway": '
            "Error GWCER102: Secret seeded-reliability/checkout-tls not found."
        )
        rows = analyze([gw], events=[event])
        self.assertEqual(len(rows), 1)
        self.assertGreater(len(rows[0]["detail"]), 100)
        self.assertTrue(rows[0]["detail"].endswith("Secret seeded-reliability/checkout-tls not found."))
        self.assertIn("Secret seeded-reliability/checkout-tls not found.", stall_report.render_table(rows))

    def test_events_v1_series_shape_is_read(self):
        gw = obj("Gateway", "edge", spec={}, status={})
        event = {
            "type": "Warning",
            "reason": "SYNC",
            "message": "m",
            "eventTime": stamp(40),
            "series": {"count": 12, "lastObservedTime": stamp(2)},
            "involvedObject": {"kind": "Gateway", "name": "edge"},
        }
        rows = analyze([gw], events=[event])
        self.assertEqual(len(rows), 1)
        self.assertIn("x12", rows[0]["detail"])


class DanglingReferences(unittest.TestCase):
    def test_gateway_listener_naming_an_absent_secret(self):
        gw = obj(
            "Gateway",
            "edge",
            spec={"gatewayClassName": "gke-l7-regional-external-managed", "listeners": [{"name": "https", "tls": {"certificateRefs": [{"kind": "Secret", "name": "edge-tls"}]}}]},
            status={},
            managed_fields=[managed(45)],
        )
        rows = analyze([gw], existing={("secrets", NAMESPACE): set()})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["heuristic"], "dangling-reference")
        self.assertEqual(rows[0]["detail"], "listeners[0].tls.certificateRefs -> Secret/edge-tls not found")
        self.assertEqual(rows[0]["stalled_for"], "45m")

    def test_deployment_envfrom_naming_an_absent_configmap(self):
        dep = healthy_deployment()
        dep["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [{"configMapRef": {"name": "web-config"}}]
        dep["metadata"]["managedFields"] = [managed(30)]
        rows = analyze([dep], existing={("configmaps", NAMESPACE): {"something-else"}})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["heuristic"], "dangling-reference")
        self.assertIn("ConfigMap/web-config not found", rows[0]["detail"])

    def test_present_and_optional_references_are_quiet(self):
        dep = healthy_deployment()
        container = dep["spec"]["template"]["spec"]["containers"][0]
        container["envFrom"] = [{"configMapRef": {"name": "web-config"}}, {"secretRef": {"name": "absent", "optional": True}}]
        dep["spec"]["template"]["spec"]["volumes"] = [{"name": "v", "configMap": {"name": "web-config"}}]
        rows = analyze([dep], existing={("configmaps", NAMESPACE): {"web-config"}, ("secrets", NAMESPACE): set()})
        self.assertEqual(rows, [])

    def test_volume_sources_are_resolved(self):
        dep = healthy_deployment()
        dep["spec"]["template"]["spec"]["volumes"] = [
            {"name": "data", "persistentVolumeClaim": {"claimName": "web-data"}},
            {"name": "tls", "secret": {"secretName": "web-tls"}},
        ]
        rows = analyze([dep], existing={("persistentvolumeclaims", NAMESPACE): set(), ("secrets", NAMESPACE): {"web-tls"}})
        self.assertEqual([r["detail"] for r in rows], ["template.spec.volumes[0].persistentVolumeClaim -> PersistentVolumeClaim/web-data not found"])

    def test_route_parent_and_backend_references(self):
        route = obj(
            "HTTPRoute",
            "web",
            spec={
                "parentRefs": [{"name": "edge"}, {"name": "shared", "namespace": "infra"}],
                "rules": [{"backendRefs": [{"name": "web", "port": 80}, {"kind": "ServiceImport", "name": "remote"}]}],
            },
            status={},
            managed_fields=[managed(60)],
        )
        existing = {
            ("gateways.gateway.networking.k8s.io", NAMESPACE): {"edge"},
            ("gateways.gateway.networking.k8s.io", "infra"): set(),
            ("services", NAMESPACE): set(),
        }
        rows = analyze([route], existing=existing)
        self.assertEqual(
            sorted(r["detail"] for r in rows),
            ["parentRefs -> infra/Gateway/shared not found", "rules[0].backendRefs -> Service/web not found"],
        )

    def test_recent_spec_is_given_time_to_settle(self):
        gw = obj("Gateway", "edge", spec={"listeners": [{"tls": {"certificateRefs": [{"name": "edge-tls"}]}}]}, status={}, managed_fields=[managed(3)])
        self.assertEqual(analyze([gw], existing={("secrets", NAMESPACE): set()}), [])
        self.assertEqual(len(analyze([gw], existing={("secrets", NAMESPACE): set()}, override=1)), 1)

    def test_unreadable_referent_kind_is_not_reported(self):
        gw = obj("Gateway", "edge", spec={"listeners": [{"tls": {"certificateRefs": [{"name": "edge-tls"}]}}]}, status={}, managed_fields=[managed(50)])
        self.assertEqual(analyze([gw], existing={}), [])

    def test_secret_contents_are_never_requested(self):
        seen = []

        def lister(resource, ns):
            seen.append(resource)
            return set()

        resolver = stall_report.NameResolver(lister=lister)
        gw = obj("Gateway", "edge", spec={"listeners": [{"tls": {"certificateRefs": [{"name": "edge-tls"}]}}]}, status={}, managed_fields=[managed(50)])
        stall_report.analyze([gw], [], resolver, NOW)
        self.assertEqual(seen, ["secrets"])


class HealthyNamespace(unittest.TestCase):
    def test_no_rows_and_zero_count(self):
        pod = obj("Pod", "web-1", spec={}, status={"phase": "Running", "conditions": [condition("Ready", "True", 300)]})
        cm = obj("ConfigMap", "web-config")
        rs = obj("ReplicaSet", "web-abc", spec={"replicas": 2}, status={"observedGeneration": 1, "replicas": 2})
        objects = [healthy_deployment(), pod, cm, rs]
        events = [warning("Pod", "web-1", 2, first_ago=200, last_ago=190, reason="Unhealthy")]
        rows = analyze(objects, events=events, existing={("configmaps", NAMESPACE): {"web-config"}})
        self.assertEqual(rows, [])
        self.assertEqual(stall_report.stalled_object_count(rows), 0)
        self.assertEqual(stall_report.render_table(rows), "OBJECT  HEURISTIC  DETAIL  STALLED_FOR")

    def test_table_caps_the_detail_column_but_the_finding_keeps_it(self):
        gw = obj("Gateway", "edge", spec={}, status={})
        event = warning("Gateway", "edge", 9, first_ago=40, last_ago=1)
        event["message"] = "x" * (stall_report.TABLE_DETAIL_MAX_CHARS + 50)
        rows = analyze([gw], events=[event])
        self.assertEqual(len(rows[0]["detail"]), len("SYNC x9: ") + stall_report.TABLE_DETAIL_MAX_CHARS + 50)
        cell = stall_report.render_table(rows).split("\n")[1].split("  ")[2]
        self.assertEqual(len(cell), stall_report.TABLE_DETAIL_MAX_CHARS)
        self.assertTrue(cell.endswith(stall_report.TRUNCATION_MARKER))

    def test_count_is_per_object_not_per_row(self):
        dep = healthy_deployment()
        dep["status"]["conditions"] = [condition("Available", "False", 30), condition("Progressing", "False", 30)]
        rows = analyze([dep])
        self.assertEqual(len(rows), 2)
        self.assertEqual(stall_report.stalled_object_count(rows), 1)


class Helpers(unittest.TestCase):
    def test_format_duration(self):
        self.assertEqual(stall_report.format_duration(30), "<1m")
        self.assertEqual(stall_report.format_duration(15 * 60), "15m")
        self.assertEqual(stall_report.format_duration(3 * 3600 + 5 * 60), "3h05m")
        self.assertEqual(stall_report.format_duration(2 * 86400 + 3600), "2d1h")

    def test_parse_time_handles_z_and_fractions(self):
        self.assertEqual(stall_report.parse_time("2026-09-09T12:00:00Z"), NOW)
        self.assertEqual(stall_report.parse_time("2026-09-09T12:00:00.123456Z"), NOW + timedelta(microseconds=123456))
        self.assertIsNone(stall_report.parse_time(None))
        self.assertIsNone(stall_report.parse_time("yesterday"))

    def test_namespaced_resources_filters_exclusions(self):
        listing = (
            "deployments.apps\nevents\nevents.events.k8s.io\nsecrets\nendpoints\npods.metrics.k8s.io\n"
            "configmaps\ncontrollerrevisions.apps\nendpointslices.discovery.k8s.io\nleases.coordination.k8s.io\n"
            "gateways.gateway.networking.k8s.io\n"
        )
        with patch.object(stall_report, "run_kubectl", return_value=(0, listing, "")):
            self.assertEqual(stall_report.namespaced_resources(), ["deployments.apps", "gateways.gateway.networking.k8s.io"])

    def test_namespaced_resources_keeps_a_partial_listing(self):
        stderr = "error: unable to retrieve the complete list of server APIs: external.metrics.k8s.io/v1beta1: the server is currently unable to handle the request"
        with patch.object(stall_report, "run_kubectl", return_value=(1, "deployments.apps\npods\n", stderr)):
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(stall_report.namespaced_resources(), ["deployments.apps", "pods"])
        self.assertIn("warning: error: unable to retrieve", err.getvalue())
        with patch.object(stall_report, "run_kubectl", return_value=(1, "", "forbidden")):
            with self.assertRaises(RuntimeError):
                stall_report.namespaced_resources()

    def test_kubectl_json_keeps_partial_output(self):
        partial = '{"kind":"List","items":[{"kind":"Deployment"}]}'
        with patch.object(stall_report, "run_kubectl", return_value=(1, partial, "error: the server could not find the requested resource")):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(stall_report.kubectl_json(["get", "x"])["items"], [{"kind": "Deployment"}])
        with patch.object(stall_report, "run_kubectl", return_value=(1, "", "boom")):
            with self.assertRaises(RuntimeError):
                stall_report.kubectl_json(["get", "x"])

    def test_kubectl_names_strips_the_resource_prefix(self):
        with patch.object(stall_report, "run_kubectl", return_value=(0, "secret/a\nsecret/b\n", "")):
            self.assertEqual(stall_report.kubectl_names("secrets", NAMESPACE), {"a", "b"})
        with patch.object(stall_report, "run_kubectl", return_value=(1, "", "forbidden")):
            self.assertIsNone(stall_report.kubectl_names("secrets", NAMESPACE))


class Exempt(unittest.TestCase):
    """The stall watch's opt-out annotation marks the rows; it hides nothing here."""

    @staticmethod
    def wedged(name, annotations=None):
        dep = healthy_deployment(name)
        dep["status"]["conditions"] = [condition("Progressing", "False", 30, "ProgressDeadlineExceeded")]
        if annotations is not None:
            dep["metadata"]["annotations"] = annotations
        return dep

    def run_main(self, objects, *argv):
        with patch.object(stall_report, "collect", return_value=(objects, [])):
            with patch.object(stall_report, "NameResolver", lambda: FakeResolver({})):
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(stall_report.main(["--namespace", NAMESPACE, *argv]), 0)
        return out.getvalue()

    def test_the_exempt_field_comes_from_the_objects_annotation(self):
        rows = analyze([
            self.wedged("exempt", {stall_report.EXEMPT_ANNOTATION: stall_report.EXEMPT_VALUE}),
            self.wedged("other-value", {stall_report.EXEMPT_ANNOTATION: "yes"}),
            self.wedged("unrelated", {"team": "payments"}),
            self.wedged("bare"),
        ])
        self.assertEqual({r["object"]: r[stall_report.EXEMPT_FIELD] for r in rows}, {
            "Deployment/exempt": True,
            "Deployment/other-value": False,
            "Deployment/unrelated": False,
            "Deployment/bare": False,
        })

    def test_json_rows_carry_the_field_and_the_count_is_unchanged(self):
        report = json.loads(self.run_main([self.wedged("web", {stall_report.EXEMPT_ANNOTATION: stall_report.EXEMPT_VALUE})], "--json"))
        self.assertEqual(report["stalled_resources"], 1)
        self.assertIs(report["findings"][0][stall_report.EXEMPT_FIELD], True)

    def test_the_table_is_the_same_with_or_without_the_annotation(self):
        exempt = self.run_main([self.wedged("web", {stall_report.EXEMPT_ANNOTATION: stall_report.EXEMPT_VALUE})])
        plain = self.run_main([self.wedged("web")])
        self.assertEqual(exempt, plain)
        self.assertEqual(exempt.splitlines()[0].split(), list(stall_report.TABLE_COLUMNS))
        self.assertEqual(exempt.splitlines()[-1], "stalled resources: 1")


class Main(unittest.TestCase):
    def test_table_output_ends_with_the_summary_line(self):
        dep = healthy_deployment()
        dep["status"]["conditions"] = [condition("Progressing", "False", 30, "ProgressDeadlineExceeded")]
        with patch.object(stall_report, "collect", return_value=([dep], [])):
            with patch.object(stall_report, "NameResolver", lambda: FakeResolver({})):
                out = io.StringIO()
                with redirect_stdout(out):
                    rc = stall_report.main(["--namespace", NAMESPACE])
        self.assertEqual(rc, 0)
        lines = out.getvalue().rstrip("\n").split("\n")
        self.assertTrue(lines[0].startswith("OBJECT"))
        self.assertIn("Deployment/web", lines[1])
        self.assertEqual(lines[-1], "stalled resources: 1")

    def test_json_output(self):
        with patch.object(stall_report, "collect", return_value=([healthy_deployment()], [])):
            with patch.object(stall_report, "NameResolver", lambda: FakeResolver({})):
                out = io.StringIO()
                with redirect_stdout(out):
                    rc = stall_report.main(["--namespace", NAMESPACE, "--json"])
        self.assertEqual(rc, 0)
        self.assertIn('"stalled_resources": 0', out.getvalue())

    def test_collect_failure_exits_two(self):
        with patch.object(stall_report, "collect", side_effect=RuntimeError("no cluster")):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(stall_report.main(["--namespace", NAMESPACE]), 2)

    def test_collect_wraps_a_single_object(self):
        single = {"kind": "Deployment", "metadata": {"name": "foo"}}
        with patch.object(stall_report, "kubectl_json", side_effect=[single, {"items": []}]):
            objects, events = stall_report.collect(NAMESPACE, "deployments/foo")
        self.assertEqual(objects, [single])
        self.assertEqual(events, [])

    def test_collect_reads_one_kind_per_call_and_only_warning_events(self):
        calls = []

        def fake_json(args):
            calls.append(args)
            return {"items": [{"kind": args[1]}]}

        with patch.object(stall_report, "kubectl_json", side_effect=fake_json):
            objects, events = stall_report.collect(NAMESPACE, "deployments,gateways,")
        self.assertEqual(calls[0], ["get", "deployments", "-n", NAMESPACE, "--show-managed-fields"])
        self.assertEqual(calls[1], ["get", "gateways", "-n", NAMESPACE, "--show-managed-fields"])
        self.assertEqual(calls[2], ["get", "events", "-n", NAMESPACE, "--field-selector", "type=Warning"])
        self.assertEqual(len(calls), 3)
        self.assertEqual([o["kind"] for o in objects], ["deployments", "gateways"])
        self.assertEqual(events, [{"kind": "events"}])

    def test_collect_keeps_the_other_kinds_when_one_listing_is_cut(self):
        """The sandbox's kubectl is the credential-proxy shim, which returns the
        prefix of an over-cap reply with exit 0 and a stderr note."""
        cut = '{"apiVersion":"v1","kind":"List","items":[{"kind":"Pod","metadata":{"name":"a'

        def fake_kubectl(args):
            if args[1] == "pods":
                return 0, cut, "credential proxy output truncated\n"
            if args[1] == "events":
                return 0, '{"items":[]}', ""
            return 0, '{"items":[{"kind":"Deployment","metadata":{"name":"web"}}]}', ""

        with patch.object(stall_report, "run_kubectl", side_effect=fake_kubectl):
            with redirect_stderr(io.StringIO()) as err:
                objects, events = stall_report.collect(NAMESPACE, "deployments,pods,replicasets")
        self.assertEqual([o["metadata"]["name"] for o in objects], ["web", "web"])
        self.assertEqual(events, [])
        self.assertIn("warning: credential proxy output truncated", err.getvalue())
        self.assertIn(f"warning: pods in {NAMESPACE} not scanned; its objects are missing from the count", err.getvalue())
        self.assertNotIn("deployments in", err.getvalue())

    def test_collect_errors_only_when_no_kind_could_be_read(self):
        with patch.object(stall_report, "run_kubectl", return_value=(1, "", "Unable to connect to the server")):
            with redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(RuntimeError) as raised:
                    stall_report.collect(NAMESPACE, "deployments,pods")
        self.assertIn("no kind could be read", str(raised.exception))
        self.assertIn("deployments, pods", str(raised.exception))
        self.assertIn("warning: pods in", err.getvalue())

    def test_collect_scans_without_events_when_they_cannot_be_read(self):
        def fake_kubectl(args):
            if args[1] == "events":
                return 0, '{"items":[{"kind":"Event","metadata":{"name":"x', "credential proxy output truncated\n"
            return 0, '{"items":[{"kind":"Deployment","metadata":{"name":"web"}}]}', ""

        with patch.object(stall_report, "run_kubectl", side_effect=fake_kubectl):
            with redirect_stderr(io.StringIO()) as err:
                objects, events = stall_report.collect(NAMESPACE, "deployments")
        self.assertEqual(len(objects), 1)
        self.assertEqual(events, [])
        self.assertIn(f"warning: events in {NAMESPACE} not read; repeating-warnings is not checked", err.getvalue())


class InProcessShimAndParallelCollection(unittest.TestCase):
    """Tests for in-process credential shim dispatch, parallel collection, and timestamp caching."""

    def setUp(self):
        stall_report._SHIM_CACHE.clear()
        stall_report._parse_time_str.cache_clear()

    def test_run_kubectl_uses_inprocess_shim_when_kubectl_matches_client(self):
        import shutil
        import tempfile
        import credential_proxy_client

        with tempfile.TemporaryDirectory() as tmp:
            shim_path = os.path.join(tmp, "kubectl")
            shutil.copyfile(credential_proxy_client.__file__, shim_path)
            os.chmod(shim_path, 0o755)
            env = {
                "CREDENTIAL_PROXY_URL": "http://127.0.0.1:8765",
                "PATH": f"{tmp}:{os.environ.get('PATH', '')}",
            }
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(
                     credential_proxy_client,
                     "execute_captured",
                     return_value=(0, '{"items":[]}\n', ""),
                 ) as exec_cap, \
                 patch.object(stall_report, "_ORIG_SUBPROCESS_RUN", stall_report.subprocess.run):
                rc, out, err = stall_report.run_kubectl(["get", "pods", "-o", "json"])
            self.assertEqual((0, '{"items":[]}\n', ""), (rc, out, err))
            exec_cap.assert_called_once_with(
                "http://127.0.0.1:8765", ["kubectl", "get", "pods", "-o", "json"]
            )

    def test_run_kubectl_falls_back_to_subprocess_when_monkeypatched_or_non_shim(self):
        import shutil
        import tempfile
        import credential_proxy_client

        with tempfile.TemporaryDirectory() as tmp:
            shim_path = os.path.join(tmp, "kubectl")
            shutil.copyfile(credential_proxy_client.__file__, shim_path)
            os.chmod(shim_path, 0o755)

            # 1. CREDENTIAL_PROXY_URL unset -> falls back to subprocess.run
            fake_completed = stall_report.subprocess.CompletedProcess(
                ["kubectl", "get", "pods"], 0, stdout="sub-out", stderr=""
            )
            env_no_url = {"CREDENTIAL_PROXY_URL": "", "PATH": f"{tmp}:{os.environ.get('PATH', '')}"}
            with patch.dict(os.environ, env_no_url, clear=False), \
                 patch.object(stall_report.subprocess, "run", return_value=fake_completed) as sub_run, \
                 patch.object(credential_proxy_client, "execute_captured") as exec_cap:
                rc, out, err = stall_report.run_kubectl(["get", "pods"])
                self.assertEqual((0, "sub-out", ""), (rc, out, err))
                sub_run.assert_called_once()
                exec_cap.assert_not_called()

            # 2.CREDENTIAL_PROXY_URL set, but subprocess.run is monkeypatched -> falls back to subprocess.run
            env_with_url = {
                "CREDENTIAL_PROXY_URL": "http://127.0.0.1:8765",
                "PATH": f"{tmp}:{os.environ.get('PATH', '')}",
            }
            with patch.dict(os.environ, env_with_url, clear=False), \
                 patch.object(stall_report.subprocess, "run", return_value=fake_completed) as sub_run, \
                 patch.object(credential_proxy_client, "execute_captured") as exec_cap:
                rc, out, err = stall_report.run_kubectl(["get", "pods"])
                self.assertEqual((0, "sub-out", ""), (rc, out, err))
                sub_run.assert_called_once()
                exec_cap.assert_not_called()

            # 3. kubectl on PATH is a different binary/script -> _shim_client() returns None
            with open(shim_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho real-kubectl\n")
            stall_report._SHIM_CACHE.clear()
            with patch.dict(os.environ, env_with_url, clear=False):
                self.assertIsNone(stall_report._shim_client())

    def test_parallel_reads_detection_respects_monkeypatching(self):
        self.assertTrue(stall_report._parallel_reads())
        with patch.object(stall_report, "run_kubectl", side_effect=stall_report.run_kubectl):
            self.assertFalse(stall_report._parallel_reads())
        with patch.object(stall_report, "kubectl_json", side_effect=stall_report.kubectl_json):
            self.assertFalse(stall_report._parallel_reads())
        with patch.object(stall_report, "kubectl_names", side_effect=stall_report.kubectl_names):
            self.assertFalse(stall_report._parallel_reads())
        with patch.object(stall_report.subprocess, "run", side_effect=stall_report.subprocess.run):
            self.assertFalse(stall_report._parallel_reads())

    def test_parallel_collect_runs_concurrently_and_preserves_deterministic_order(self):
        import threading
        import time

        # 4 resources + 1 events call = 5 concurrent calls (<= COLLECT_WORKERS=6)
        barrier = threading.Barrier(5, timeout=5.0)

        def concurrent_kubectl(args):
            barrier.wait()
            kind = args[1]
            # Deliberately stagger completion in reverse order so earlier resources finish last
            if kind == "deployments":
                time.sleep(0.03)
                return 0, '{"items":[{"kind":"Deployment","metadata":{"name":"d1"}}]}', "dep-warn\n"
            if kind == "pods":
                time.sleep(0.02)
                return 1, "", "pods-boom"
            if kind == "statefulsets":
                time.sleep(0.01)
                return 0, '{"items":[{"kind":"StatefulSet","metadata":{"name":"s1"}}]}', "sts-warn\n"
            if kind == "gateways":
                return 0, '{"items":[{"kind":"Gateway","metadata":{"name":"g1"}}]}', "gw-warn\n"
            if kind == "events":
                return 0, '{"items":[{"kind":"Event","metadata":{"name":"e1"}}]}', "ev-warn\n"
            raise AssertionError(f"unexpected args: {args}")

        err_buf = io.StringIO()
        with patch.object(stall_report, "run_kubectl", side_effect=concurrent_kubectl), \
             patch.object(stall_report, "_parallel_reads", return_value=True), \
             redirect_stderr(err_buf):
            objects, events = stall_report.collect(
                NAMESPACE, "deployments,pods,statefulsets,gateways"
            )

        # Objects must be in exact resource request order: deployments, statefulsets, gateways
        self.assertEqual(
            [(o["kind"], o["metadata"]["name"]) for o in objects],
            [("Deployment", "d1"), ("StatefulSet", "s1"), ("Gateway", "g1")],
        )
        self.assertEqual([e["metadata"]["name"] for e in events], ["e1"])

        # Warnings must be emitted in exact sequential order despite reverse completion times
        stderr_lines = [line.strip() for line in err_buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(
            stderr_lines,
            [
                "warning: dep-warn",
                "warning: pods-boom",
                f"warning: pods in {NAMESPACE} not scanned; its objects are missing from the count: kubectl get pods -n {NAMESPACE} --show-managed-fields failed (1): pods-boom",
                "warning: sts-warn",
                "warning: gw-warn",
                "warning: ev-warn",
            ],
        )

    def test_parallel_prefetch_references_populates_cache_in_deterministic_order(self):
        import threading
        import time

        gw = obj(
            "Gateway",
            "edge",
            spec={
                "listeners": [
                    {"name": "https", "tls": {"certificateRefs": [{"kind": "Secret", "name": "edge-tls"}]}},
                ]
            },
            status={},
            managed_fields=[managed(45)],
        )
        dep = healthy_deployment("web")
        dep["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [
            {"configMapRef": {"name": "web-cm"}},
        ]
        dep["spec"]["template"]["spec"]["volumes"] = [
            {"name": "pvc", "persistentVolumeClaim": {"claimName": "web-pvc"}},
        ]
        dep["metadata"]["managedFields"] = [managed(45)]

        barrier = threading.Barrier(3, timeout=5.0)
        calls = []
        calls_lock = threading.Lock()

        def concurrent_names_kubectl(args):
            with calls_lock:
                calls.append(tuple(args))
            barrier.wait()
            resource = args[1]
            if resource == "secrets":
                time.sleep(0.03)
                return 1, "", "forbidden-secrets"
            if resource == "configmaps":
                time.sleep(0.01)
                return 0, "configmap/web-cm\n", ""
            if resource == "persistentvolumeclaims":
                return 1, "", "forbidden-pvcs"
            raise AssertionError(f"unexpected args: {args}")

        resolver = stall_report.NameResolver()
        err_buf = io.StringIO()
        with patch.object(stall_report, "run_kubectl", side_effect=concurrent_names_kubectl) as mocked_run, \
             patch.object(stall_report, "_parallel_reads", return_value=True), \
             redirect_stderr(err_buf):
            stall_report.prefetch_references(resolver, [gw, dep], NOW)
            self.assertEqual(mocked_run.call_count, 3)
            # Subsequent analyze() must use the prefetched resolver._cache with zero additional kubectl calls
            findings = stall_report.analyze([gw, dep], [], resolver, NOW)
            self.assertEqual(mocked_run.call_count, 3)

        self.assertEqual(findings, [])
        self.assertIsNone(resolver._cache[("secrets", NAMESPACE)])
        self.assertEqual(resolver._cache[("configmaps", NAMESPACE)], {"web-cm"})
        self.assertIsNone(resolver._cache[("persistentvolumeclaims", NAMESPACE)])

        # Stderr warnings from failed referent listings must follow the exact discovery order (secrets then pvcs)
        stderr_lines = [line.strip() for line in err_buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(
            stderr_lines,
            [
                f"warning: cannot list secrets in {NAMESPACE}; references to secrets are not checked: forbidden-secrets",
                f"warning: cannot list persistentvolumeclaims in {NAMESPACE}; references to persistentvolumeclaims are not checked: forbidden-pvcs",
            ],
        )

    def test_parse_time_str_lru_cache_hits_and_edge_cases(self):
        stall_report._parse_time_str.cache_clear()
        ts = "2026-09-09T12:00:00Z"
        first = stall_report.parse_time(ts)
        second = stall_report.parse_time(ts)
        self.assertEqual(first, NOW)
        self.assertIs(first, second)
        info = stall_report._parse_time_str.cache_info()
        self.assertEqual(info.hits, 1)
        self.assertEqual(info.misses, 1)

        # Empty strings and non-strings bypass or return None cleanly
        self.assertIsNone(stall_report.parse_time(""))
        self.assertIsNone(stall_report.parse_time(None))
        self.assertIsNone(stall_report.parse_time(12345))
        self.assertIsNone(stall_report._parse_time_str(""))

        # Malformed timestamps return None and are cached
        self.assertIsNone(stall_report.parse_time("not-a-timestamp"))
        self.assertIsNone(stall_report.parse_time("not-a-timestamp"))
        self.assertEqual(stall_report._parse_time_str.cache_info().hits, 2)

        # Naive ISO-8601 string gets UTC tzinfo attached
        naive = stall_report.parse_time("2026-09-09T12:00:00")
        self.assertEqual(naive, NOW)

    def test_prefetch_references_single_key_and_zero_key_paths(self):
        resolver = stall_report.NameResolver()
        # 0 keys: healthy deployment with no references -> 0 kubectl calls
        dep_no_refs = healthy_deployment("web")
        with patch.object(stall_report, "run_kubectl") as mocked_run, \
             patch.object(stall_report, "_parallel_reads", return_value=True):
            stall_report.prefetch_references(resolver, [dep_no_refs], NOW)
            mocked_run.assert_not_called()

        # 1 key: single reference -> direct synchronous call without ThreadPoolExecutor
        gw = obj(
            "Gateway",
            "edge",
            spec={
                "listeners": [
                    {"name": "https", "tls": {"certificateRefs": [{"kind": "Secret", "name": "edge-tls"}]}},
                ]
            },
            status={},
            managed_fields=[managed(45)],
        )
        with patch.object(
            stall_report, "run_kubectl", return_value=(0, "secret/edge-tls\n", "")
        ) as mocked_run, patch.object(stall_report, "_parallel_reads", return_value=True):
            stall_report.prefetch_references(resolver, [gw], NOW)
            mocked_run.assert_called_once_with(
                ["get", "secrets", "-n", NAMESPACE, "-o", "name"]
            )
        self.assertEqual(resolver._cache[("secrets", NAMESPACE)], {"edge-tls"})

    def test_parallel_collect_total_failure_raises_without_emitting_events_warning(self):
        def failing_kubectl(args):
            kind = args[1]
            if kind == "events":
                return 1, "", "events-should-not-be-warned"
            return 1, "", f"{kind}-failed"

        err_buf = io.StringIO()
        with patch.object(stall_report, "run_kubectl", side_effect=failing_kubectl), \
             patch.object(stall_report, "_parallel_reads", return_value=True), \
             redirect_stderr(err_buf):
            with self.assertRaises(RuntimeError) as ctx:
                stall_report.collect(NAMESPACE, "deployments,pods")

        self.assertIn(f"no kind could be read in {NAMESPACE}: deployments, pods", str(ctx.exception))
        self.assertNotIn("events-should-not-be-warned", err_buf.getvalue())
        self.assertNotIn("events in", err_buf.getvalue())

    def test_late_binding_and_monkeypatch_guards_for_resolvers_and_kubectl(self):
        # 1. KUBECTL != "kubectl" disables _parallel_reads() and _shim_client()
        with patch.object(stall_report, "KUBECTL", "/custom/kubectl"):
            self.assertFalse(stall_report._parallel_reads())
            self.assertIsNone(stall_report._shim_client())

        # 2. NameResolver() with no args picks up post-import patch on stall_report.kubectl_names
        with patch.object(stall_report, "kubectl_names", return_value={"patched-secret"}) as patched_names:
            resolver = stall_report.NameResolver()
            self.assertTrue(resolver.exists("Secret", NAMESPACE, "patched-secret"))
            patched_names.assert_called_once_with("secrets", NAMESPACE)

        # 3. ScaleResolver() with no args picks up post-import patch on stall_report.kubectl_json
        with patch.object(stall_report, "kubectl_json", return_value={"items": []}) as patched_json:
            scale = stall_report.ScaleResolver()
            self.assertEqual(scale._items("get", "deployments"), [])
            patched_json.assert_called_once_with(["get", "deployments"])

        # 4. Patching NameResolver.exists disables prefetch_references
        gw = obj(
            "Gateway",
            "edge",
            spec={
                "listeners": [
                    {"name": "https", "tls": {"certificateRefs": [{"kind": "Secret", "name": "edge-tls"}]}},
                ]
            },
            status={},
            managed_fields=[managed(45)],
        )
        resolver = stall_report.NameResolver()
        with patch.object(stall_report.NameResolver, "exists", return_value=True), \
             patch.object(stall_report, "run_kubectl") as mocked_run:
            stall_report.prefetch_references(resolver, [gw], NOW)
            mocked_run.assert_not_called()

    def test_shim_client_size_guard_standalone_fallback_and_thread_safety(self):
        import shutil
        import tempfile
        import threading
        import credential_proxy_client

        with tempfile.TemporaryDirectory() as tmp:
            shim_path = os.path.join(tmp, "kubectl")

            # 1. File with different size than credential_proxy_client.py is rejected via stat without open()
            with open(shim_path, "wb") as handle:
                handle.write(b"#!/bin/sh\necho short\n")
            os.chmod(shim_path, 0o755)
            stall_report._SHIM_CACHE.clear()
            with patch("builtins.open", side_effect=AssertionError("open() should not be called on size mismatch")):
                self.assertIsNone(stall_report._load_shim_client(shim_path))

            # 2. File larger than _MAX_SHIM_BYTES is rejected immediately
            with open(shim_path, "wb") as handle:
                handle.write(b"x" * (stall_report._MAX_SHIM_BYTES + 10))
            stall_report._SHIM_CACHE.clear()
            self.assertIsNone(stall_report._load_shim_client(shim_path))

            # 3. Standalone fallback loads credential_proxy_client from PATH shim when not on sys.path
            shutil.copyfile(credential_proxy_client.__file__, shim_path)
            os.chmod(shim_path, 0o755)
            stall_report._SHIM_CACHE.clear()
            saved_mod = sys.modules.pop("credential_proxy_client", None)
            try:
                with patch.object(sys, "path", []):
                    loaded = stall_report._load_shim_client(shim_path)
                    self.assertIsNotNone(loaded)
                    self.assertTrue(hasattr(loaded, "execute_captured"))
            finally:
                if saved_mod is not None:
                    sys.modules["credential_proxy_client"] = saved_mod

            # 4. Concurrent cold-cache calls to _shim_client() across 8 threads
            stall_report._SHIM_CACHE.clear()
            env = {
                "CREDENTIAL_PROXY_URL": "http://127.0.0.1:8765",
                "PATH": f"{tmp}:{os.environ.get('PATH', '')}",
            }
            barrier = threading.Barrier(8, timeout=5.0)
            results = [None] * 8

            def worker(idx):
                barrier.wait()
                results[idx] = stall_report._shim_client()

            with patch.dict(os.environ, env, clear=False), \
                 patch.object(stall_report, "_ORIG_SUBPROCESS_RUN", stall_report.subprocess.run):
                threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=5.0)
            for res in results:
                self.assertIs(res, credential_proxy_client)

    def test_parse_kubectl_json_rejects_non_dict_json(self):
        for payload in ("[1, 2, 3]", "null", '"string"', "42"):
            with self.subTest(payload=payload):
                with self.assertRaises(RuntimeError) as ctx:
                    stall_report._parse_kubectl_json(["get", "pods"], 0, payload, "")
                self.assertIn("returned non-object JSON", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
