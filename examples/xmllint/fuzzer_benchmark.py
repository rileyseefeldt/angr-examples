#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import angr
import claripy
from angr import sim_options as so
from angr.rustylib.fuzzer import ClientStats, Fuzzer, InMemoryCorpus

TARGET_ARGS = ["--noout", "--nonet", "--recover", "--noent"]
SEED_CORPUS = [b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&y;</a>"]
DEFAULT_TARGET_PATH = Path(__file__).resolve().parent / "xmllint_bin"
BENCHMARK_DURATION = 30


def apply_fn(state: angr.SimState, data: bytes) -> None:
    project = state.project
    if project is not None:
        return_addr = project.factory.cc().return_addr
        if return_addr is not None:
            return_addr.set_value(state, 0xDEADBEEF)

    state.posix.stdin.content = [(claripy.BVV(data), claripy.BVV(len(data), state.arch.bits))]
    if hasattr(state.posix.stdin, "pos"):
        state.posix.stdin.pos = 0


def find_afl_qemu_trace() -> Path | None:
    path = shutil.which("afl-qemu-trace")
    if path:
        return Path(path)

    afl_path = os.environ.get("AFL_PATH")
    if not afl_path:
        return None

    candidate = Path(afl_path) / "afl-qemu-trace"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate

    return None


def run_angr(target: Path, duration: int) -> tuple[int, float]:
    args = [str(target), *TARGET_ARGS, "-"]
    project = angr.Project(str(target), auto_load_libs=True, use_sim_procedures=False)
    state = project.factory.entry_state(
        args=args,
        add_options={
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
            so.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    fuzzer = Fuzzer(
        base_state=state,
        apply_fn=apply_fn,
        corpus=InMemoryCorpus.from_list(SEED_CORPUS),
        solutions=InMemoryCorpus(),
        timeout=0,
        seed=12751,
    )

    deadline = time.monotonic() + duration
    last_stats: ClientStats | None = None
    while time.monotonic() < deadline:

        def callback(stats: ClientStats, _event_type: str, _client_id: int):
            nonlocal last_stats
            last_stats = stats

        fuzzer.run_once(progress_callback=callback)

    if last_stats is None:
        raise RuntimeError("angr run produced no stats")
    return last_stats.executions, last_stats.execs_per_sec


def run_afl(target: Path, duration: int) -> tuple[int, float]:
    if not shutil.which("afl-fuzz"):
        raise RuntimeError("AFL++ missing: afl-fuzz not found")

    afl_qemu = find_afl_qemu_trace()
    if afl_qemu is None:
        raise RuntimeError("AFL++ QEMU mode missing: afl-qemu-trace not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"
        output_dir = Path(tmpdir) / "output"
        corpus_dir.mkdir()
        output_dir.mkdir()

        for i, data in enumerate(SEED_CORPUS):
            (corpus_dir / f"seed_{i}").write_bytes(data)

        env = os.environ.copy()
        env.setdefault("AFL_PATH", str(afl_qemu.parent))
        env.setdefault("AFL_NO_UI", "1")
        env.setdefault("AFL_SKIP_CPUFREQ", "1")
        env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")

        cmd = [
            "afl-fuzz",
            "-V",
            str(duration),
            "-i",
            str(corpus_dir),
            "-o",
            str(output_dir),
            "-Q",
            "--",
            str(target),
            *TARGET_ARGS,
            "@@",
        ]
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=duration + 30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"AFL++ failed with exit code {proc.returncode}\n"
                f"stderr:\n{proc.stderr[-2000:]}\n"
                f"stdout:\n{proc.stdout[-2000:]}"
            )

        stats_file = output_dir / "default" / "fuzzer_stats"
        if not stats_file.exists():
            raise RuntimeError("AFL++ run did not produce output/default/fuzzer_stats")

        stats: dict[str, str] = {}
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                stats[key.strip()] = value.strip()

        return int(stats.get("execs_done", 0)), float(stats.get("execs_per_sec", 0))


def compare_angr_vs_afl() -> tuple[tuple[int, float], tuple[int, float]]:
    target = DEFAULT_TARGET_PATH.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    print(f"target: {target}")
    print(f"duration: {BENCHMARK_DURATION}s")

    angr_result = run_angr(target, BENCHMARK_DURATION)
    afl_result = run_afl(target, BENCHMARK_DURATION)
    print(f"angr: {angr_result[0]} execs, {angr_result[1]:.2f} execs/sec")
    print(f"AFL++: {afl_result[0]} execs, {afl_result[1]:.2f} execs/sec")
    if angr_result[1] > 0:
        print(f"AFL++/angr speedup: {afl_result[1] / angr_result[1]:.2f}x")

    return angr_result, afl_result


def test_angr_execs_per_second() -> None:
    target = DEFAULT_TARGET_PATH.resolve()
    executions, eps = run_angr(target, BENCHMARK_DURATION)
    assert executions > 0
    print(f"\nangr: {executions} execs, {eps:.2f} execs/sec")


def test_afl_execs_per_second() -> None:
    target = DEFAULT_TARGET_PATH.resolve()
    executions, eps = run_afl(target, BENCHMARK_DURATION)
    assert executions > 0
    print(f"\nAFL++: {executions} execs, {eps:.2f} execs/sec")


if __name__ == "__main__":
    compare_angr_vs_afl()
