#!/usr/bin/env python3
"""Crash-detection example using the angr/icicle fuzzer against a vulnerable
xmllint binary (libxml2 2.9.1, compiled without stack protector).

The crash input is a deeply-nested XML document (~55 000 levels of ``<a>``
tags).  When parsed with ``--huge`` (which removes libxml2's default 256-depth
safety limit), the recursive parser overflows the stack and triggers SIGSEGV.

This script:
  1. Builds the crash input.
  2. Uses DeterministicMutator to feed it through the angr/icicle fuzzer.
  3. Asserts the fuzzer classified it as a solution (crash).
  4. Confirms the crash by running the native binary directly.

Compare with ``solve.py`` which demonstrates coverage-guided corpus growth
on the *patched* ``xmllint_bin`` (libxml2 2.9.14).
"""

import os
import subprocess

import angr
import claripy
from angr import sim_options as so
from angr.rustylib.fuzzer import (
    DeterministicMutator,
    Fuzzer,
    InMemoryCorpus,
)


# ---------------------------------------------------------------------------
# Crash input and corpus
# ---------------------------------------------------------------------------

CRASH_DEPTH = 55000

def make_crash_input(depth=CRASH_DEPTH):
    """Deeply-nested XML that overflows the parser stack in libxml2 2.9.1
    when the ``--huge`` flag removes the 256-depth safety limit."""
    return ("<a>" * depth + "x" + "</a>" * depth).encode()


def apply_fn(state: angr.SimState, data: bytes) -> None:
    """Inject fuzzed input into stdin.

    _fuzzer_breakpoints is set on the base_state before the fuzzer runs,
    so every copy already has exit's address as a breakpoint.
    """
    s = state.posix.stdin
    s.content = [(claripy.BVV(data), claripy.BVV(len(data), state.arch.bits))]
    if hasattr(s, "pos"):
        s.pos = 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(verbose=True):
    target = os.path.join(os.path.dirname(__file__), "xmllint_old")
    xmllint_args = [target, "--noout", "--nonet", "--recover", "--noent", "--huge", "-"]

    project = angr.Project(target, auto_load_libs=True, use_sim_procedures=False)

    # With use_sim_procedures=False the loader still registers
    # IFuncResolvers for IFUNC symbols.  Remove them so icicle executes
    # the resolved implementations natively instead of round-tripping
    # through Python for every libc string call.
    from angr.procedures.linux_loader.sim_loader import IFuncResolver

    for addr, proc in list(project._sim_procedures.items()):
        if isinstance(proc, IFuncResolver):
            project.unhook(addr)

    base_state = project.factory.entry_state(
        args=xmllint_args,
        add_options={
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
            so.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Set a breakpoint at exit so the executor stops when main returns.
    # ConcreteLibcStartMain writes exit's address to [RSP] as a return
    # sentinel, so ret from main jumps to exit; the breakpoint here is
    # what actually tells the executor to stop.
    exit_addr = project.loader.find_symbol("exit").rebased_addr
    base_state.globals["_fuzzer_breakpoints"] = [exit_addr]

    # -- Build the fuzzer with the crash input as the only mutation --
    crash_input = make_crash_input()
    safe_input = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&y;</a>"

    corpus = InMemoryCorpus.from_list([safe_input])
    solutions = InMemoryCorpus()

    mutator = DeterministicMutator([crash_input])
    fuzzer = Fuzzer(
        base_state=base_state,
        apply_fn=apply_fn,
        corpus=corpus,
        solutions=solutions,
        timeout=0,
        seed=0,
        max_mutations=1,
        mutator=mutator,
    )

    if verbose:
        print(f"Target: {target}")
        print(f"Crash input: {len(crash_input)} bytes ({CRASH_DEPTH} nesting depth)")
        print("Running fuzzer...")

    fuzzer.run_once()

    num_solutions = len(fuzzer.solutions())
    if verbose:
        print(f"Corpus: {len(fuzzer.corpus())} entries")
        print(f"Solutions (crashes): {num_solutions}")

    return num_solutions, target, crash_input


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test():
    num_solutions, target, crash_input = main(verbose=False)

    # 1. The angr fuzzer must classify the input as a crash
    assert num_solutions >= 1, "Fuzzer should have reported the crash as a solution"

    # 2. Confirm the native binary actually crashes
    result = subprocess.run(
        [target, "--noout", "--nonet", "--recover", "--noent", "--huge", "-"],
        input=crash_input,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode < 0, (
        f"Expected native crash (negative return code), got {result.returncode}"
    )
    print(f"Confirmed native crash: signal {-result.returncode}")
    return True


if __name__ == "__main__":
    num_solutions, target, crash_input = main(verbose=True)

    if num_solutions >= 1:
        print("\n--- Native confirmation ---")
        result = subprocess.run(
            [target, "--noout", "--nonet", "--recover", "--noent", "--huge", "-"],
            input=crash_input,
            capture_output=True,
            timeout=60,
        )
        if result.returncode < 0:
            print(f"Native binary crashed with signal {-result.returncode} (SIGSEGV)")
        else:
            print(f"WARNING: Native binary exited {result.returncode} (no crash)")
    else:
        print("WARNING: Fuzzer did not report any crashes")
