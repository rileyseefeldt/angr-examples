#!/usr/bin/env python3

import os
import shutil

import angr
import claripy
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus, ClientStats
from angr import sim_options as so


def create_corpus() -> list[bytes]:
    return [
        b"<a/>",
        b"<a>b</a>",
        b"<?xml version='1.0'?><r/>",
        b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>",
    ]


def apply_fn(state: angr.SimState, data: bytes) -> angr.SimState:
    # Arrange a recognizable return address
    state.project.factory.cc().return_addr.set_value(state, 0xDEADBEEF)
    s = state.posix.stdin
    s.content = [(claripy.BVV(data), claripy.BVV(len(data), state.arch.bits))]
    if hasattr(s, "pos"):
        s.pos = 0
    return state


def main() -> None:
    target = shutil.which("xmllint")
    if not target or not os.path.exists(target):
        raise SystemExit("xmllint not found")

    # xmllint CLI: read from stdin with '-' and keep output quiet/nonet
    xmllint_args = [target, "--noout", "--nonet", "--recover", "--noent", "-"]

    project = angr.Project(target, auto_load_libs=True, use_sim_procedures=False)
    base_state = project.factory.entry_state(
        args=xmllint_args,
        add_options={
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
            so.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    corpus = InMemoryCorpus.from_list(create_corpus())
    solutions = InMemoryCorpus()

    fuzzer = Fuzzer(
        base_state=base_state,
        apply_fn=apply_fn,
        corpus=corpus,
        solutions=solutions,
        timeout=100,
        seed=0,
    )

    def progress_callback(stats: ClientStats, type_: str, _client_id: int) -> None:
        print(
            f"[{type_}] C: {stats.corpus_size}, O: {stats.objective_size}, E: {stats.executions}, E/s: {stats.execs_per_sec_pretty}, Cov: {stats.edges_hit}/{stats.edges_total}"
        )

    fuzzer.run_once(progress_callback=progress_callback)
    print(f"Corpus now has {len(fuzzer.corpus())} inputs.")
    print(f"Corpus inputs: \n{fuzzer.corpus().to_bytes_list()}")
    print(f"Found {len(fuzzer.solutions())} solutions.")
    print(f"Found the following solutions: \n{fuzzer.solutions().to_bytes_list()}")


if __name__ == "__main__":
    main()
