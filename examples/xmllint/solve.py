#!/usr/bin/env python3

import os
import claripy
import angr
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus, ClientStats
from angr import sim_options as so


def create_corpus():
    return [
        b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&y;</a>",  # one byte flip ('y'->'x') enables entity resolution path
    ]


def apply_fn(state: angr.SimState, data: bytes) -> None:
    # Arrange a recognizable return address
    p = state.project
    if p is not None:
        ra = p.factory.cc().return_addr
        if ra is not None:
            ra.set_value(state, 0xDEADBEEF)
    s = state.posix.stdin
    s.content = [(claripy.BVV(data), claripy.BVV(len(data), state.arch.bits))]
    if hasattr(s, "pos"):
        s.pos = 0


class _StopFuzzing(Exception):
    pass


# SEED VALUE NEEDED FOR TEST
def main(verbose=True, seed=12751, stop_early=True):
    target = os.path.join(os.path.dirname(__file__), "xmllint_bin")

    # xmllint CLI: read from stdin with '-' and keep output quiet/nonet
    xmllint_args = [target, "--noout", "--nonet", "--recover", "--noent", "-"]

    project = angr.Project(target, auto_load_libs=False, use_sim_procedures=True)
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
        timeout=0,
        seed=seed,
    )

    def progress_callback(stats: ClientStats, type_: str, _client_id: int):
        msg = (
            f"[{type_}] "
            f"C: {stats.corpus_size}, O: {stats.objective_size}, "
            f"E: {stats.executions}, E/s: {stats.execs_per_sec_pretty}, "
            f"Cov: {stats.edges_hit}/{stats.edges_total}"
        )
        if verbose:
            print(msg, flush=True)
        if stop_early and type_ == "Testcase":
            raise _StopFuzzing()

    before = len(fuzzer.corpus())

    try:
        fuzzer.run_once(
            progress_callback=progress_callback if verbose or stop_early else None
        )
    except _StopFuzzing:
        pass

    # Can remove this part once monitor.rs is fixed
    except BaseException as e:
        # The Rust fuzzer code panics when Python raises an exception in the callback.
        # This is a known bug (FIXME in monitor.rs:113). The PanicException wraps our
        # _StopFuzzing exception, so we check if it's our expected early-stop signal.
        if type(e).__name__ == "PanicException" and "_StopFuzzing" in str(e):
            pass  # Expected: our stop signal triggered the panic
        else:
            raise  # Re-raise unexpected exceptions

    after = len(fuzzer.corpus())
    new_input = fuzzer.corpus()[before]
    if verbose:
        print(f"Corpus now has {len(fuzzer.corpus())} inputs.", flush=True)
        print(f"Corpus inputs: \n{fuzzer.corpus().to_bytes_list()}", flush=True)
        print(f"Found {len(fuzzer.solutions())} solutions.", flush=True)
        print(
            f"Found the following solutions: \n{fuzzer.solutions().to_bytes_list()}",
            flush=True,
        )
    return before, after, new_input


def test():
    before, after, new_input = main(verbose=False, stop_early=True)
    # Basic corpus growth sanity check
    assert after == before + 1

    # Desired mutation check: change entity reference '&y;' -> '&x;'
    expected = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>"
    assert new_input == expected
    return True


if __name__ == "__main__":
    main()
