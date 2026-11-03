"""The broker's memory telemetry (#4315): what the container holds, read from
the kernel rather than estimated from the budget's constants.

Three readers and a sampler. `MemoryReader` reads the cgroup v2 files and
/proc; `ChildPeakTracker` reads the children's ru_maxrss after each reap and
attributes a rise to the tool just reaped; `MemorySampler` writes a log line
at start, at each step of the container's high-water, and as a warning when
the limit was reached; `ProxyMetrics` renders the snapshot as series. Every
file is faked under a temporary directory, so the tests say what each figure
is read from and what an unreadable one does: absent, never zero.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
import json
import logging
import re
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import credential_proxy
from credential_proxy import (
    ChildPeakTracker,
    CommandExecutor,
    CredentialProxyHandler,
    MemoryReader,
    MemorySampler,
    MemorySnapshot,
    ProxyMetrics,
    _JSON_STREAM_SLICE_CHARS,
    _LARGE_OUTPUT_THRESHOLD_BYTES,
    _MALLOC_ARENA_SETTINGS,
    _bounded_text,
    _capture_output,
    _configure_malloc_arena,
    _reap,
)

_MIB = 1024 * 1024
_KIB = 1024
# The gkedemos2 proxy container on 2026-10-29, 2Gi limit, a near-empty scope.
_CURRENT = 251711488
_PEAK = 569466880
_LIMIT = 2147483648
_ANON = 116756480
_FILE = 111996928
_BROKER_RSS_KB = 108748
_BROKER_PEAK_KB = 152900
_ENVOY_RSS_KB = 69916
_ENVOY_PEAK_KB = 69916
_ENVOY_PID = "11"
_OTHER_PID = "1"
_SERIES = re.compile(r"^(?P<name>[a-z_]+)(?:\{(?P<labels>[^}]*)\})? (?P<value>-?[0-9.]+(?:e[+-]?[0-9]+)?)$")
_LABEL_PAIR = re.compile(r'([a-z_]+)="((?:[^"\\]|\\.)*)"')


def _families(exposition: str) -> dict[str, dict[frozenset, float]]:
    families: dict[str, dict[frozenset, float]] = {}
    for line in exposition.splitlines():
        if line.startswith("#"):
            continue
        match = _SERIES.match(line)
        assert match, f"not a Prometheus text line: {line!r}"
        labels = frozenset(_LABEL_PAIR.findall(match.group("labels") or ""))
        families.setdefault(match.group("name"), {})[labels] = float(match.group("value"))
    return families


def _series(families, name, **labels):
    return families[name][frozenset(labels.items())]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _fake_cgroup(root: Path, *, limit: str = str(_LIMIT), events: str = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n") -> Path:
    cgroup = root / "cgroup"
    _write(cgroup / "memory.current", f"{_CURRENT}\n")
    _write(cgroup / "memory.peak", f"{_PEAK}\n")
    _write(cgroup / "memory.max", f"{limit}\n")
    _write(cgroup / "memory.stat", f"anon {_ANON}\nfile {_FILE}\nkernel 22712320\nkernel_stack 458752\n")
    _write(cgroup / "memory.events", events)
    return cgroup


def _fake_proc(root: Path) -> Path:
    proc = root / "proc"
    _write(proc / "self" / "status", f"Name:\tpython3\nVmPeak:\t 643156 kB\nVmHWM:\t  {_BROKER_PEAK_KB} kB\nVmRSS:\t  {_BROKER_RSS_KB} kB\n")
    _write(proc / _ENVOY_PID / "comm", "envoy\n")
    _write(proc / _ENVOY_PID / "status", f"Name:\tenvoy\nVmHWM:\t   {_ENVOY_PEAK_KB} kB\nVmRSS:\t   {_ENVOY_RSS_KB} kB\n")
    _write(proc / _OTHER_PID / "comm", "bash\n")
    _write(proc / _OTHER_PID / "status", "Name:\tbash\nVmHWM:\t 3336 kB\nVmRSS:\t 3336 kB\n")
    return proc


class MemoryReaderTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tracker = ChildPeakTracker()

    def reader(self, *, cgroup_dir: Path | None = None, proc_root: Path | None = None) -> MemoryReader:
        return MemoryReader(
            self.tracker,
            cgroup_dir=cgroup_dir if cgroup_dir is not None else _fake_cgroup(self.root),
            proc_root=proc_root if proc_root is not None else _fake_proc(self.root),
        )

    def test_the_cgroup_figures_are_read_by_kind(self):
        snapshot = self.reader().read()
        self.assertEqual(
            {"current": _CURRENT, "peak": _PEAK, "limit": _LIMIT, "anon": _ANON, "file": _FILE},
            snapshot.cgroup,
        )
        self.assertEqual({"high": 0, "max": 0, "oom": 0, "oom_kill": 0}, snapshot.events)

    def test_a_limit_of_max_and_an_unreadable_file_leave_the_kind_absent(self):
        cgroup = _fake_cgroup(self.root, limit="max")
        (cgroup / "memory.peak").unlink()
        (cgroup / "memory.events").write_text("not a counter line\n")
        snapshot = self.reader(cgroup_dir=cgroup).read()
        self.assertNotIn("limit", snapshot.cgroup)
        self.assertNotIn("peak", snapshot.cgroup)
        self.assertEqual(_CURRENT, snapshot.cgroup["current"])
        self.assertEqual({}, snapshot.events)

    def test_the_broker_and_envoy_are_read_from_proc_in_bytes(self):
        snapshot = self.reader().read()
        self.assertEqual(
            {
                "broker": {"rss": _BROKER_RSS_KB * _KIB, "peak": _BROKER_PEAK_KB * _KIB},
                "envoy": {"rss": _ENVOY_RSS_KB * _KIB, "peak": _ENVOY_PEAK_KB * _KIB},
            },
            snapshot.processes,
        )

    def test_envoy_is_found_by_comm_and_found_again_when_its_pid_changes(self):
        proc = _fake_proc(self.root)
        reader = self.reader(proc_root=proc)
        self.assertIn("envoy", reader.read().processes)
        # The pid is kept between reads, and a pid that now names another
        # process is dropped rather than read as Envoy.
        (proc / _ENVOY_PID / "comm").write_text("sleep\n")
        self.assertNotIn("envoy", reader.read().processes)
        _write(proc / "13" / "comm", "envoy\n")
        _write(proc / "13" / "status", "VmHWM:\t 70000 kB\nVmRSS:\t 70000 kB\n")
        self.assertEqual(70000 * _KIB, reader.read().processes["envoy"]["rss"])

    def test_a_container_without_envoy_has_no_envoy_series(self):
        proc = _fake_proc(self.root)
        (proc / _ENVOY_PID / "comm").unlink()
        self.assertEqual(["broker"], sorted(self.reader(proc_root=proc).read().processes))

    def test_the_children_come_from_the_tracker(self):
        tracker = ChildPeakTracker()
        tracker.record("gcloud", 120 * _MIB)
        tracker.record("kubectl", 600 * _MIB)
        reader = MemoryReader(tracker, cgroup_dir=_fake_cgroup(self.root), proc_root=_fake_proc(self.root))
        snapshot = reader.read()
        self.assertEqual({"gcloud": 120 * _MIB, "kubectl": 600 * _MIB}, snapshot.children)
        self.assertEqual(("kubectl", 600 * _MIB), snapshot.largest_child)


class ChildPeakTrackerTest(unittest.TestCase):
    def test_each_tools_figure_is_its_own_and_the_largest_is_logged(self):
        tracker = ChildPeakTracker()
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO) as logs:
            self.assertTrue(tracker.record("gcloud", 100 * _MIB))
            # A smaller child moves its own tool's figure only when larger
            # than that tool's, and never the overall; no line for it.
            self.assertFalse(tracker.record("kubectl", 60 * _MIB))
            self.assertTrue(tracker.record("kubectl", 432 * _MIB))
            self.assertFalse(tracker.record("gcloud", 90 * _MIB))
        self.assertEqual({"gcloud": 100 * _MIB, "kubectl": 432 * _MIB}, tracker.snapshot()[0])
        self.assertEqual(("kubectl", 432 * _MIB), tracker.snapshot()[1])
        self.assertEqual(
            ["largest child so far tool=gcloud peak_rss=100MiB", "largest child so far tool=kubectl peak_rss=432MiB"],
            [record.getMessage() for record in logs.records],
        )

    def test_a_reap_without_a_peak_records_nothing(self):
        tracker = ChildPeakTracker()
        self.assertFalse(tracker.record("kubectl", None))
        self.assertFalse(tracker.record("kubectl", 0))
        self.assertEqual(({}, None), tracker.snapshot())

    def test_the_bootstrap_command_is_recorded_under_its_own_label(self):
        # The bootstrap is the process's first child, so the children's
        # high-water after it is its tree's; it is recorded as `bootstrap`
        # and the first brokered command does not inherit it.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        executor = CommandExecutor(timeout_seconds=5, max_output_bytes=1024, state_dir=temp.name, scoped_pool=None)
        executor.child_peaks = ChildPeakTracker()
        executor.bootstrap("true")
        by_tool, largest = executor.child_peaks.snapshot()
        self.assertEqual(["bootstrap"], sorted(by_tool))
        self.assertGreater(by_tool["bootstrap"], 0)
        self.assertEqual("bootstrap", largest[0])

    def test_an_empty_bootstrap_records_nothing(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        executor = CommandExecutor(timeout_seconds=5, max_output_bytes=1024, state_dir=temp.name, scoped_pool=None)
        executor.child_peaks = ChildPeakTracker()
        executor.bootstrap("")
        self.assertEqual(({}, None), executor.child_peaks.snapshot())

    def test_the_executor_records_each_reaped_child_under_the_tools_label(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stub_dir = Path(temp.name) / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "kubectl"
        stub.write_text("#!/bin/sh\necho ok\n")
        stub.chmod(0o755)
        executor = CommandExecutor(timeout_seconds=5, max_output_bytes=1024, state_dir=temp.name, scoped_pool=None)
        executor.executables["kubectl"] = str(stub)
        with mock.patch.object(executor, "child_peaks") as peaks:
            result = executor.execute(["kubectl", "get", "pods"])
        self.assertEqual(0, result.exit_code, result.stderr)
        peaks.record.assert_called_once()
        tool, peak = peaks.record.call_args.args
        self.assertEqual("kubectl", tool)
        self.assertGreater(peak, 0)


class ReapTest(unittest.TestCase):
    """`_reap` is the one place a brokered child is waited for: wait4, so the
    child's own rusage comes back, and Popen's view set from it."""

    def test_a_blocking_reap_returns_the_childs_own_peak_and_sets_the_returncode(self):
        process = subprocess.Popen(["sh", "-c", "exit 3"])
        reaped, peak = _reap(process, None)
        self.assertTrue(reaped)
        self.assertGreater(peak, 0)
        self.assertEqual(3, process.returncode)
        # Popen agrees and does not wait again.
        self.assertEqual(3, process.wait())
        self.assertEqual(3, process.poll())

    def test_a_signal_is_the_negative_number_as_popen_reports_it(self):
        process = subprocess.Popen(["sleep", "30"])
        process.kill()
        reaped, peak = _reap(process, None)
        self.assertTrue(reaped)
        self.assertEqual(-9, process.returncode)
        self.assertIsNotNone(peak)

    def test_a_timed_reap_gives_up_on_a_running_child_and_takes_it_once_it_exits(self):
        process = subprocess.Popen(["sleep", "30"])
        try:
            started = time.monotonic()
            self.assertEqual((False, None), _reap(process, 0))
            self.assertEqual((False, None), _reap(process, 0.05))
            self.assertLess(time.monotonic() - started, 1)
            self.assertIsNone(process.returncode)
        finally:
            process.kill()
        reaped, peak = _reap(process, 1)
        self.assertTrue(reaped)
        self.assertEqual(-9, process.returncode)

    def test_a_child_already_reaped_is_taken_from_popens_view_with_no_peak(self):
        process = subprocess.Popen(["sh", "-c", "exit 2"])
        self.assertEqual(2, process.wait())
        self.assertEqual((True, None), _reap(process, None))

    def test_capture_output_carries_the_peak_on_the_ordinary_path(self):
        process = subprocess.Popen(["sh", "-c", "echo out; echo err >&2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        captured = _capture_output(process, stdin=None, limit=4096, timeout=5)
        self.assertEqual((b"out\n", b"err\n", 0), (captured.stdout, captured.stderr, process.returncode))
        self.assertGreater(captured.peak_rss_bytes, 0)

    def test_capture_output_carries_the_peak_when_the_child_closed_its_pipes_early(self):
        # The pipes close but the command runs on: the stepped poll path.
        process = subprocess.Popen(["sh", "-c", "exec >/dev/null 2>&1; sleep 0.3; exit 0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        captured = _capture_output(process, stdin=None, limit=4096, timeout=5)
        self.assertEqual(0, process.returncode)
        self.assertFalse(captured.timed_out)
        self.assertGreater(captured.peak_rss_bytes, 0)

    def test_capture_output_carries_the_peak_of_a_timed_out_child(self):
        process = subprocess.Popen(["sh", "-c", "sleep 30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        captured = _capture_output(process, stdin=None, limit=4096, timeout=0.2)
        self.assertTrue(captured.timed_out)
        self.assertIsNotNone(process.returncode)
        self.assertGreater(captured.peak_rss_bytes, 0)


class _Readings:
    def __init__(self, *snapshots: MemorySnapshot) -> None:
        self._snapshots = list(snapshots)

    def read(self) -> MemorySnapshot:
        return self._snapshots.pop(0) if len(self._snapshots) > 1 else self._snapshots[0]


def _snapshot(peak: int, *, events: dict[str, int] | None = None, children=None) -> MemorySnapshot:
    return MemorySnapshot(
        cgroup={"current": _CURRENT, "peak": peak, "limit": _LIMIT, "anon": _ANON, "file": _FILE},
        events=events if events is not None else {"high": 0, "max": 0, "oom": 0, "oom_kill": 0},
        processes={"broker": {"rss": 110 * _MIB, "peak": 150 * _MIB}, "envoy": {"rss": 68 * _MIB, "peak": 68 * _MIB}},
        children=children or {"kubectl": 432 * _MIB},
        largest_child=("kubectl", 432 * _MIB),
    )


class MemorySamplerTest(unittest.TestCase):
    def test_the_first_tick_logs_the_breakdown_and_a_steady_broker_logs_nothing_more(self):
        sampler = MemorySampler(_Readings(_snapshot(543 * _MIB)), step_bytes=64 * _MIB)
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO) as logs:
            line = sampler.tick()
        self.assertEqual(
            "memory at start: cgroup_peak=543MiB current=240MiB limit=2048MiB anon=111MiB file=106MiB "
            "broker_rss=110MiB broker_peak=150MiB envoy_rss=68MiB envoy_peak=68MiB largest_child=kubectl:432MiB "
            "events high=0 max=0 oom=0 oom_kill=0",
            line,
        )
        self.assertEqual(logging.INFO, logs.records[0].levelno)
        self.assertIsNone(sampler.tick())

    def test_a_high_water_a_step_up_logs_and_one_under_the_step_does_not(self):
        sampler = MemorySampler(_Readings(_snapshot(543 * _MIB), _snapshot(600 * _MIB), _snapshot(610 * _MIB)), step_bytes=64 * _MIB)
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO):
            sampler.tick()
        self.assertIsNone(sampler.tick())
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO):
            line = sampler.tick()
        self.assertTrue(line.startswith("memory high-water: cgroup_peak=610MiB"), line)

    def test_an_event_counter_moving_is_a_warning(self):
        sampler = MemorySampler(
            _Readings(_snapshot(543 * _MIB), _snapshot(2048 * _MIB, events={"high": 0, "max": 3, "oom": 0, "oom_kill": 0})),
        )
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO):
            sampler.tick()
        with self.assertLogs(credential_proxy.LOGGER, level=logging.WARNING) as logs:
            line = sampler.tick()
        self.assertTrue(line.startswith("memory limit reached: cgroup_peak=2048MiB"), line)
        self.assertIn("events high=0 max=3 oom=0 oom_kill=0", line)
        self.assertEqual(1, len(logs.records))
        # The same count again is not news.
        self.assertIsNone(sampler.tick())

    def test_without_memory_peak_the_sampler_steps_on_its_own_high_water_of_current(self):
        # A kernel before 5.19 has no memory.peak: the sampler then keeps the
        # largest `current` it has seen and writes the high-water line as that
        # climbs, instead of falling silent after the first line.
        def without_peak(current):
            snapshot = _snapshot(0)
            cgroup = dict(snapshot.cgroup)
            del cgroup["peak"]
            cgroup["current"] = current
            return snapshot._replace(cgroup=cgroup)

        sampler = MemorySampler(
            _Readings(without_peak(300 * _MIB), without_peak(320 * _MIB), without_peak(400 * _MIB), without_peak(200 * _MIB)),
            step_bytes=64 * _MIB,
        )
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO) as logs:
            self.assertTrue(sampler.tick().startswith("memory at start: cgroup_peak=? current=300MiB"))
        self.assertIsNone(sampler.tick())
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO):
            self.assertTrue(sampler.tick().startswith("memory high-water: cgroup_peak=? current=400MiB"))
        self.assertIsNone(sampler.tick())

    def test_a_reader_that_fails_does_not_end_the_thread(self):
        reader = mock.Mock()
        reader.read.side_effect = [OSError("gone"), _snapshot(543 * _MIB)]
        stop = mock.Mock()
        stop.is_set.side_effect = [False, False, True]
        sampler = MemorySampler(reader, interval_s=0, stop=stop)
        with self.assertLogs(credential_proxy.LOGGER, level=logging.INFO) as logs:
            sampler.run()
        self.assertEqual(["memory sample failed type=OSError"], [r.getMessage() for r in logs.records if "failed" in r.getMessage()])
        self.assertEqual(2, reader.read.call_count)

    def test_a_snapshot_with_nothing_readable_still_describes_itself(self):
        empty = MemorySnapshot(cgroup={}, events={}, processes={}, children={}, largest_child=None)
        self.assertEqual("cgroup_peak=? current=? limit=?", MemorySampler.describe(empty))


class MemorySeriesTest(unittest.TestCase):
    def test_the_series_render_from_the_reader_at_scrape_time(self):
        metrics = ProxyMetrics()
        snapshot = _snapshot(543 * _MIB, events={"max": 2, "oom_kill": 0}, children={"kubectl": 432 * _MIB, "gcloud": 102 * _MIB})
        metrics.set_memory_reader(lambda: snapshot)
        families = _families(metrics.render())
        self.assertEqual(_LIMIT, _series(families, "kubeagents_credential_proxy_cgroup_memory_bytes", kind="limit"))
        self.assertEqual(543 * _MIB, _series(families, "kubeagents_credential_proxy_cgroup_memory_bytes", kind="peak"))
        self.assertEqual(_ANON, _series(families, "kubeagents_credential_proxy_cgroup_memory_bytes", kind="anon"))
        self.assertEqual(2, _series(families, "kubeagents_credential_proxy_cgroup_memory_events_total", event="max"))
        self.assertEqual(150 * _MIB, _series(families, "kubeagents_credential_proxy_process_memory_bytes", process="broker", kind="peak"))
        self.assertEqual(68 * _MIB, _series(families, "kubeagents_credential_proxy_process_memory_bytes", process="envoy", kind="rss"))
        self.assertEqual(432 * _MIB, _series(families, "kubeagents_credential_proxy_child_peak_rss_bytes", tool="kubectl"))
        self.assertEqual(102 * _MIB, _series(families, "kubeagents_credential_proxy_child_peak_rss_bytes", tool="gcloud"))
        self.assertIn("# TYPE kubeagents_credential_proxy_cgroup_memory_events_total counter", metrics.render())

    def test_a_registry_without_a_reader_renders_no_memory_series(self):
        text = ProxyMetrics().render()
        for name in (
            "kubeagents_credential_proxy_cgroup_memory_bytes",
            "kubeagents_credential_proxy_cgroup_memory_events_total",
            "kubeagents_credential_proxy_process_memory_bytes",
            "kubeagents_credential_proxy_child_peak_rss_bytes",
        ):
            self.assertNotIn(name, text)

    def test_the_label_values_are_the_closed_vocabularies(self):
        metrics = ProxyMetrics()
        metrics.set_memory_reader(lambda: _snapshot(543 * _MIB))
        for line in metrics.render().splitlines():
            if line.startswith("kubeagents_credential_proxy_cgroup_memory_bytes"):
                kind = dict(_LABEL_PAIR.findall(line))["kind"]
                self.assertIn(kind, {"current", "peak", "limit", "anon", "file"})


class MallocArenaConfigurationTest(unittest.TestCase):
    def test_configure_malloc_arena_applies_settings_and_returns_bool(self):
        self.assertIsInstance(credential_proxy._MALLOC_ARENA_CONFIGURED, bool)
        self.assertEqual(
            (
                (credential_proxy._M_ARENA_MAX, 1),
                (credential_proxy._M_MMAP_THRESHOLD, 131_072),
                (credential_proxy._M_TRIM_THRESHOLD, 131_072),
            ),
            _MALLOC_ARENA_SETTINGS,
        )
        fake_libc = mock.MagicMock()
        fake_libc.mallopt.return_value = 1
        with mock.patch.object(credential_proxy.ctypes, "CDLL", return_value=fake_libc) as cdll:
            self.assertTrue(_configure_malloc_arena())
        cdll.assert_called_once_with("libc.so.6")
        self.assertEqual(
            [mock.call(param, value) for param, value in _MALLOC_ARENA_SETTINGS],
            fake_libc.mallopt.call_args_list,
        )

    def test_configure_malloc_arena_handles_missing_or_failing_mallopt_and_oserror(self):
        with mock.patch.object(credential_proxy.ctypes, "CDLL", side_effect=OSError("no libc")):
            self.assertFalse(_configure_malloc_arena())

        libc_without_mallopt = object()
        with mock.patch.object(credential_proxy.ctypes, "CDLL", return_value=libc_without_mallopt):
            self.assertFalse(_configure_malloc_arena())

        failing_libc = mock.MagicMock()
        failing_libc.mallopt.return_value = 0
        with mock.patch.object(credential_proxy.ctypes, "CDLL", return_value=failing_libc):
            self.assertFalse(_configure_malloc_arena())

        partial_libc = mock.MagicMock()
        partial_libc.mallopt.side_effect = [1, 0, 1]
        with mock.patch.object(credential_proxy.ctypes, "CDLL", return_value=partial_libc):
            self.assertFalse(_configure_malloc_arena())
        self.assertEqual(len(_MALLOC_ARENA_SETTINGS), partial_libc.mallopt.call_count)


class BoundedTextBytearrayTest(unittest.TestCase):
    def test_bounded_text_decodes_bytearray_below_and_at_limit(self):
        text, truncated = _bounded_text(bytearray(b"hello world\n"), 64)
        self.assertEqual("hello world\n", text)
        self.assertFalse(truncated)

        utf8_raw = bytearray("café€".encode("utf-8"))
        text_exact, truncated_exact = _bounded_text(utf8_raw, len(utf8_raw))
        self.assertEqual("café€", text_exact)
        self.assertFalse(truncated_exact)

    def test_bounded_text_handles_zero_and_negative_limits(self):
        self.assertEqual(("", False), _bounded_text(bytearray(), 0))
        self.assertEqual(("", False), _bounded_text(bytearray(), -5))
        self.assertEqual(("", True), _bounded_text(bytearray(b"non-empty"), 0))
        self.assertEqual(("", True), _bounded_text(bytearray(b"non-empty"), -1))

    def test_bounded_text_truncates_bytearray_above_limit_on_utf8_character_boundary(self):
        # "a" (1B) + "é" (2B) + "€" (3B) + "𐍈" (4B) = 10 bytes in UTF-8.
        raw = bytearray("aé€𐍈".encode("utf-8"))
        for limit, expected in (
            (1, "a"),
            (2, "a"),
            (3, "aé"),
            (4, "aé"),
            (5, "aé"),
            (6, "aé€"),
            (9, "aé€"),
        ):
            with self.subTest(limit=limit):
                text, truncated = _bounded_text(raw, limit)
                self.assertEqual(expected, text)
                self.assertTrue(truncated)
                self.assertLessEqual(len(text.encode("utf-8")), limit)

        # Invalid UTF-8 bytes expand to 3-byte U+FFFD replacement characters
        # and are still cut so the UTF-8 byte length stays within `limit`.
        invalid = bytearray(b"\xff" * 10)
        text_inv, truncated_inv = _bounded_text(invalid, 10)
        self.assertEqual("\ufffd" * 3, text_inv)
        self.assertTrue(truncated_inv)
        self.assertLessEqual(len(text_inv.encode("utf-8")), 10)

    def test_bounded_text_multi_chunk_bytearray_straddling_64kib_boundary_and_clears_large_buffer(self):
        chunk_bytes = credential_proxy.OUTPUT_READ_CHUNK_BYTES
        # Place a 4-byte UTF-8 character ("𐍈") straddling the 65536-byte chunk boundary,
        # and size the buffer above _LARGE_OUTPUT_THRESHOLD_BYTES so the incremental
        # path clears the bytearray before joining.
        prefix = b"a" * (chunk_bytes - 2)
        straddle = "𐍈".encode("utf-8")
        suffix = b"b" * (_LARGE_OUTPUT_THRESHOLD_BYTES - len(prefix) - len(straddle) + 4096)
        raw = bytearray(prefix + straddle + suffix)
        total_len = len(raw)

        # Cut inside the straddling 4-byte character (only 1 byte after `prefix` fits):
        text_cut, truncated_cut = _bounded_text(raw, len(prefix) + 1)
        self.assertTrue(truncated_cut)
        self.assertEqual("a" * (chunk_bytes - 2), text_cut)
        self.assertEqual(0, len(raw))

        # Cut right after the straddling 4-byte character:
        raw2 = bytearray(prefix + straddle + suffix)
        text_inc, truncated_inc = _bounded_text(raw2, len(prefix) + len(straddle))
        self.assertTrue(truncated_inc)
        self.assertEqual(("a" * (chunk_bytes - 2)) + "𐍈", text_inc)
        self.assertEqual(0, len(raw2))

        # Invalid byte forcing incremental decode across the full multi-chunk buffer:
        raw3 = bytearray(prefix + straddle + b"\xff" + suffix)
        text_full, truncated_full = _bounded_text(raw3, total_len + 16)
        self.assertFalse(truncated_full)
        self.assertIn("𐍈\ufffd", text_full)
        self.assertEqual(0, len(raw3))


class _CountingLock:
    def __init__(self, wrapped: threading.Lock) -> None:
        self._wrapped = wrapped
        self.entries = 0

    def __enter__(self) -> None:
        self._wrapped.acquire()
        self.entries += 1

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._wrapped.release()


class CaptureOutputBytearrayTest(unittest.TestCase):
    def test_capture_output_raw_bytearray_returns_mutable_bytearray_buffers(self):
        process = subprocess.Popen(
            ["sh", "-c", "printf 'out-bytes'; printf 'err-bytes' >&2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        captured = _capture_output(process, stdin=None, limit=4096, timeout=5, _raw_bytearray=True)
        self.assertIsInstance(captured.stdout, bytearray)
        self.assertIsInstance(captured.stderr, bytearray)
        self.assertEqual(bytearray(b"out-bytes"), captured.stdout)
        self.assertEqual(bytearray(b"err-bytes"), captured.stderr)
        self.assertFalse(captured.truncated)

    def test_capture_output_default_returns_bytes_and_serializes_large_payloads(self):
        size = _LARGE_OUTPUT_THRESHOLD_BYTES + 16384
        counting_lock = _CountingLock(credential_proxy._LARGE_OUTPUT_LOCK)

        process = subprocess.Popen(
            ["python3", "-c", f"import sys; sys.stdout.write('A' * {size}); sys.stderr.write('B' * 32)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Also verify that combined stdout + stderr >= threshold acquires the lock
        # even when each stream alone is below the threshold.
        half = (_LARGE_OUTPUT_THRESHOLD_BYTES // 2) + 4096
        process_combined = subprocess.Popen(
            ["python3", "-c", f"import sys; sys.stdout.write('C' * {half}); sys.stderr.write('D' * {half})"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with mock.patch.object(credential_proxy, "_LARGE_OUTPUT_LOCK", counting_lock):
            captured = _capture_output(process, stdin=None, limit=size + 1024, timeout=10)
            captured_combined = _capture_output(process_combined, stdin=None, limit=size + 1024, timeout=10)
        self.assertIsInstance(captured.stdout, bytes)
        self.assertIsInstance(captured.stderr, bytes)
        self.assertEqual(b"A" * size, captured.stdout)
        self.assertEqual(b"B" * 32, captured.stderr)
        self.assertEqual(b"C" * half, captured_combined.stdout)
        self.assertEqual(b"D" * half, captured_combined.stderr)
        self.assertEqual(2, counting_lock.entries)


class StreamingJsonResponseTest(unittest.TestCase):
    def _make_handler(self):
        handler = CredentialProxyHandler.__new__(CredentialProxyHandler)
        handler.connection = mock.MagicMock()
        handler.close_connection = False
        handler.status_sent = None
        handler.headers_sent = []
        handler.writes = []

        def send_response(status):
            handler.status_sent = status

        def send_header(key, value):
            handler.headers_sent.append((key, value))

        def end_headers():
            pass

        handler.send_response = send_response
        handler.send_header = send_header
        handler.end_headers = end_headers
        handler.wfile = mock.MagicMock()
        handler.wfile.write.side_effect = lambda data: handler.writes.append(bytes(data))
        return handler

    def test_json_clears_payload_and_streams_large_ascii_in_slices(self):
        for payload_chars in (_LARGE_OUTPUT_THRESHOLD_BYTES + 50_000, 3 * _JSON_STREAM_SLICE_CHARS + 12345):
            with self.subTest(payload_chars=payload_chars):
                handler = self._make_handler()
                expected_stdout = "x" * payload_chars
                payload = {
                    "status": "completed",
                    "exitCode": 0,
                    "stdout": expected_stdout,
                    "stderr": "",
                    "durationMs": 12,
                    "truncated": False,
                    "timedOut": False,
                }
                expected_copy = dict(payload)

                handler._json(HTTPStatus.OK, payload, clear_payload=True)

                self.assertEqual({}, payload)
                self.assertEqual(HTTPStatus.OK, handler.status_sent)
                self.assertGreater(len(handler.writes), 1)
                for chunk in handler.writes:
                    self.assertLessEqual(len(chunk), _JSON_STREAM_SLICE_CHARS)
                raw_body = b"".join(handler.writes)
                headers_dict = dict(handler.headers_sent)
                self.assertEqual(str(len(raw_body)), headers_dict["Content-Length"])
                self.assertEqual("application/json", headers_dict["Content-Type"])
                self.assertEqual(expected_copy, json.loads(raw_body.decode("utf-8")))

    def test_json_non_ascii_large_payload_streams_in_slices_with_exact_content_length(self):
        for marker in ("é\ufffd", "𐍈✓"):
            with self.subTest(marker=marker):
                handler = self._make_handler()
                expected_stdout = (marker * (_LARGE_OUTPUT_THRESHOLD_BYTES // 2)) + '"\n\\tail'
                payload = {
                    "status": "completed",
                    "exitCode": 0,
                    "stdout": expected_stdout,
                    "stderr": "",
                }
                expected_copy = dict(payload)

                handler._json(HTTPStatus.OK, payload, clear_payload=True)

                self.assertEqual({}, payload)
                self.assertGreater(len(handler.writes), 1)
                for chunk in handler.writes:
                    self.assertLessEqual(len(chunk), _JSON_STREAM_SLICE_CHARS)
                raw_body = b"".join(handler.writes)
                headers_dict = dict(handler.headers_sent)
                self.assertEqual(str(len(raw_body)), headers_dict["Content-Length"])
                self.assertEqual(expected_copy, json.loads(raw_body.decode("utf-8")))

    def test_json_combined_and_nested_large_payloads_acquire_lock_and_round_trip(self):
        half = (_LARGE_OUTPUT_THRESHOLD_BYTES // 2) + 8192
        counting_lock = _CountingLock(credential_proxy._LARGE_OUTPUT_LOCK)
        handler = self._make_handler()
        payload = {
            "status": "completed",
            "stdout": "s" * half,
            "stderr": "e" * half,
            "nested": [{"content": "n" * 1024, "ok": True, "Null": None}],
        }
        expected_copy = json.loads(json.dumps(payload))
        with mock.patch.object(credential_proxy, "_LARGE_OUTPUT_LOCK", counting_lock):
            handler._json(HTTPStatus.OK, payload, clear_payload=True)
        self.assertEqual(1, counting_lock.entries)
        self.assertEqual({}, payload)
        self.assertGreater(len(handler.writes), 1)
        raw_body = b"".join(handler.writes)
        self.assertEqual(expected_copy, json.loads(raw_body.decode("utf-8")))

    def test_json_mid_stream_oserror_marks_close_connection_and_logs_warning(self):
        handler = self._make_handler()
        payload = {
            "status": "completed",
            "stdout": "x" * (2 * _JSON_STREAM_SLICE_CHARS + 4096),
            "stderr": "",
        }
        calls = 0

        def fail_on_second_chunk(data):
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise BrokenPipeError("peer closed")
            handler.writes.append(bytes(data))

        handler.wfile.write.side_effect = fail_on_second_chunk
        with self.assertLogs(credential_proxy.LOGGER, level=logging.WARNING) as logs:
            handler._json(HTTPStatus.OK, payload, clear_payload=True)
        self.assertTrue(handler.close_connection)
        self.assertEqual({}, payload)
        self.assertEqual(1, len(handler.writes))
        self.assertTrue(
            any("response not delivered status=200" in rec.getMessage() and "type=BrokenPipeError" in rec.getMessage() for rec in logs.records),
            [rec.getMessage() for rec in logs.records],
        )

    def test_do_post_exec_passes_clear_payload_only_to_default_json(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stub_dir = Path(temp.name) / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "kubectl"
        stub.write_text("#!/bin/sh\nprintf 'pod-a\\n'\n", encoding="utf-8")
        stub.chmod(0o755)
        executor = CommandExecutor(
            timeout_seconds=5,
            max_output_bytes=4096,
            state_dir=temp.name,
            scoped_pool=None,
        )
        executor.executables["kubectl"] = str(stub)

        req_bytes = json.dumps({"requestId": "req-1", "argv": ["kubectl", "get", "pods"]}).encode("utf-8")

        def setup_exec_handler():
            h = self._make_handler()
            h.path = "/v1/exec"
            h.executor = executor
            h.metrics = ProxyMetrics()
            h.authenticator = credential_proxy.NullAuthenticator()
            h.policy = credential_proxy.Policy(rules=[], blocked_message="blocked")
            h.max_request_bytes = 65536
            h.enforce_read_only = False
            h.headers = {"Content-Length": str(len(req_bytes))}
            h.rfile = credential_proxy.io.BytesIO(req_bytes)
            return h

        # 1. With default _json, do_POST passes clear_payload=True.
        handler_default = setup_exec_handler()
        seen_clear_flags: list[bool] = []
        orig_encode = CredentialProxyHandler._encode_json_chunks

        def spy_encode(payload, *, clear_payload):
            seen_clear_flags.append(clear_payload)
            return orig_encode(payload, clear_payload=clear_payload)

        with (
            mock.patch.object(CredentialProxyHandler, "_payload_has_large_text", return_value=True),
            mock.patch.object(CredentialProxyHandler, "_encode_json_chunks", staticmethod(spy_encode)),
        ):
            handler_default.do_POST()
        self.assertEqual([True], seen_clear_flags)
        self.assertEqual(HTTPStatus.OK, handler_default.status_sent)

        # 2. When _json is overridden on the instance with a 2-arg callable, do_POST
        # calls it without clear_payload keyword argument.
        handler_custom = setup_exec_handler()
        recorded: list[tuple[HTTPStatus, dict]] = []
        handler_custom._json = lambda status, body: recorded.append((status, dict(body)))
        handler_custom.do_POST()
        self.assertEqual(1, len(recorded))
        self.assertEqual(HTTPStatus.OK, recorded[0][0])
        self.assertEqual("pod-a\n", recorded[0][1]["stdout"])


class ConcurrentLargeOutputExecuteTest(unittest.TestCase):
    def test_concurrent_large_output_executes_serialize_under_lock_and_clear_bytearrays(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stub_dir = Path(temp.name) / "bin"
        stub_dir.mkdir()
        size = _LARGE_OUTPUT_THRESHOLD_BYTES + 32768
        stub = stub_dir / "kubectl"
        stub.write_text(
            f"#!/usr/bin/env python3\nimport sys\nsys.stdout.write('P' * {size})\nsys.stderr.write('E' * {size})\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        executor = CommandExecutor(
            timeout_seconds=15,
            max_output_bytes=size + 65536,
            state_dir=temp.name,
            scoped_pool=None,
            max_concurrent_commands=4,
        )
        executor.executables["kubectl"] = str(stub)

        real_bounded_text = credential_proxy._bounded_text
        state_lock = threading.Lock()
        active_in_bounded_text = 0
        max_concurrent_in_bounded_text = 0
        seen_bytearrays: list[bytearray] = []

        def tracking_bounded_text(raw, limit):
            nonlocal active_in_bounded_text, max_concurrent_in_bounded_text
            with state_lock:
                active_in_bounded_text += 1
                if active_in_bounded_text > max_concurrent_in_bounded_text:
                    max_concurrent_in_bounded_text = active_in_bounded_text
                if isinstance(raw, bytearray):
                    seen_bytearrays.append(raw)
            try:
                time.sleep(0.01)
                return real_bounded_text(raw, limit)
            finally:
                with state_lock:
                    active_in_bounded_text -= 1

        with mock.patch.object(credential_proxy, "_bounded_text", tracking_bounded_text):
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(executor.execute, ["kubectl", "get", "pods"]) for _ in range(4)]
                results = [f.result() for f in futures]

        self.assertEqual(1, max_concurrent_in_bounded_text)
        self.assertEqual(8, len(seen_bytearrays))
        for buf in seen_bytearrays:
            self.assertEqual(0, len(buf))
        for res in results:
            self.assertEqual(0, res.exit_code)
            self.assertEqual("P" * size, res.stdout)
            self.assertEqual("E" * size, res.stderr)
            self.assertFalse(res.truncated)

    def test_execute_preserves_bytes_in_reused_mock_captured_output_and_skips_decode_when_abandoned(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stub_dir = Path(temp.name) / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "kubectl"
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
        executor = CommandExecutor(
            timeout_seconds=5,
            max_output_bytes=4096,
            state_dir=temp.name,
            scoped_pool=None,
        )
        executor.executables["kubectl"] = str(stub)

        fake_captured = credential_proxy._CapturedOutput(
            stdout=b"reusable-stdout\n",
            stderr=b"reusable-stderr\n",
            truncated=False,
            timed_out=False,
            abandoned=False,
            peak_rss_bytes=1024,
        )

        def fake_capture_cleanup(process, *args, **kwargs):
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            process.wait()
            return fake_captured

        with mock.patch.object(credential_proxy, "_capture_output", side_effect=fake_capture_cleanup):
            first = executor.execute(["kubectl", "get", "pods"])
            second = executor.execute(["kubectl", "get", "pods"])
        self.assertEqual("reusable-stdout\n", first.stdout)
        self.assertEqual("reusable-stderr\n", first.stderr)
        self.assertEqual("reusable-stdout\n", second.stdout)
        self.assertEqual("reusable-stderr\n", second.stderr)

        abandoned_out = bytearray(b"X" * (_LARGE_OUTPUT_THRESHOLD_BYTES + 1024))
        abandoned_err = bytearray(b"Y" * (_LARGE_OUTPUT_THRESHOLD_BYTES + 1024))
        abandoned_captured = credential_proxy._CapturedOutput(
            stdout=abandoned_out,
            stderr=abandoned_err,
            truncated=False,
            timed_out=False,
            abandoned=True,
            peak_rss_bytes=1024,
        )

        def abandoned_capture_cleanup(process, *args, **kwargs):
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            process.wait()
            return abandoned_captured

        with (
            mock.patch.object(credential_proxy, "_capture_output", side_effect=abandoned_capture_cleanup),
            mock.patch.object(credential_proxy, "_bounded_text") as bounded_spy,
        ):
            abandoned_res = executor.execute(["kubectl", "get", "pods"])
        self.assertTrue(abandoned_res.abandoned)
        self.assertEqual("", abandoned_res.stdout)
        self.assertEqual("", abandoned_res.stderr)
        self.assertEqual(0, len(abandoned_out))
        self.assertEqual(0, len(abandoned_err))
        bounded_spy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
