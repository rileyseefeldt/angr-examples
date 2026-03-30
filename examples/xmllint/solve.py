#!/usr/bin/env python3

import os
import struct
import time

import angr
import claripy
from angr import sim_options as so
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus, ClientStats
from angr.sim_procedure import SimProcedure
from archinfo import Endness



# ---------------------------------------------------------------------------
# Workaround hooks for concrete (icicle) execution of dynamically-linked
# binaries.  These will move into angr proper in a follow-up PR.
# ---------------------------------------------------------------------------

def _extract_libc_start_main_args(state, main, argc, argv, init, fini):
    from angr.procedures.glibc.__libc_start_main import __libc_start_main  # noqa: N812
    return __libc_start_main._extract_args(state, main, argc, argv, init, fini)


def _initialize_libc_data(proc):
    from angr.procedures.glibc.__libc_start_main import __libc_start_main  # noqa: N812
    __libc_start_main._initialize_b_loc_table(proc)
    __libc_start_main._initialize_tolower_loc_table(proc)
    __libc_start_main._initialize_toupper_loc_table(proc)
    __libc_start_main._initialize_errno(proc)


class _ConcreteLibcStartMain(SimProcedure):
    """Lightweight __libc_start_main that skips glibc init and jumps to main.

    Passes real argc/argv and uses ``exit`` as main's return sentinel.
    """

    NO_RET = True

    def run(self, main, argc, argv, init, fini):
        main, argc, argv, _, _ = _extract_libc_start_main_args(
            self.state, main, argc, argv, init, fini
        )

        _initialize_libc_data(self)

        self.state.regs.rdi = argc
        self.state.regs.rsi = argv
        envp = argv + (argc + 1) * self.state.arch.bytes
        self.state.regs.rdx = envp

        sentinel = self._resolve_exit_addr()
        self.state.memory.store(
            self.state.regs.sp,
            claripy.BVV(sentinel, self.state.arch.bits),
            endness=self.state.arch.memory_endness,
        )
        self.jump(main)

    def _resolve_exit_addr(self):
        proj = self.project
        for name in ("exit", "_exit", "_Exit"):
            sym = proj.loader.find_symbol(name)
            if sym is not None:
                return sym.rebased_addr
        raise ValueError("Cannot find exit symbol for return sentinel")


class _ConcreteClockGettime(SimProcedure):
    """Stub clock_gettime — the real one dispatches through the vDSO which
    icicle doesn't map."""

    def run(self, which_clock, timespec_ptr):  # noqa: ARG002
        if self.state.solver.is_true(timespec_ptr == 0):
            return -1
        flt = time.time()
        self.state.mem[timespec_ptr].struct.timespec = {
            "tv_sec": int(flt),
            "tv_nsec": int(flt * 1000000000) % 1000000000,
        }
        return 0


def resolve_got_entries(project):
    """Eagerly resolve GOT entries (equivalent to LD_BIND_NOW=1).

    CLE resolves symbols but doesn't always patch the GOT, leaving entries
    pointing to ld-linux's unmapped lazy resolver.
    """
    arch = project.arch
    word_size = arch.bytes
    fmt = (">" if arch.memory_endness == Endness.BE else "<") + ("I" if word_size == 4 else "Q")

    patches = {}
    for obj in project.loader.all_objects:
        for reloc in obj.relocs:
            if not reloc.resolved or not reloc.resolvedby:
                continue
            got_addr = getattr(reloc, "rebased_addr", None)
            if not got_addr:
                continue
            target = reloc.resolvedby.rebased_addr
            cur = struct.unpack(fmt, project.loader.memory.load(got_addr, word_size))[0]
            if cur != target:
                patches[got_addr] = struct.pack(fmt, target)

    return patches


def setup_concrete_hooks(project):
    """Install hooks needed for icicle concrete execution of dynamically-linked binaries."""
    from angr.procedures.libc.exit import exit as ExitProcedure
    from angr.procedures.glibc.__ctype_b_loc import __ctype_b_loc  # noqa: N812
    from angr.procedures.glibc.__ctype_tolower_loc import __ctype_tolower_loc  # noqa: N812
    from angr.procedures.glibc.__ctype_toupper_loc import __ctype_toupper_loc  # noqa: N812

    sym = project.loader.find_symbol("__libc_start_main")
    if sym is not None and sym.rebased_addr not in project._sim_procedures:
        project.hook(sym.rebased_addr, _ConcreteLibcStartMain())

    for name in ("exit", "_exit", "_Exit"):
        sym = project.loader.find_symbol(name)
        if sym is not None and sym.rebased_addr not in project._sim_procedures:
            project.hook(sym.rebased_addr, ExitProcedure())

    for name in ("clock_gettime", "__clock_gettime"):
        sym = project.loader.find_symbol(name)
        if sym is not None and sym.rebased_addr not in project._sim_procedures:
            project.hook(sym.rebased_addr, _ConcreteClockGettime())

    for name, proc_cls in [
        ("__ctype_b_loc", __ctype_b_loc),
        ("__ctype_tolower_loc", __ctype_tolower_loc),
        ("__ctype_toupper_loc", __ctype_toupper_loc),
    ]:
        sym = project.loader.find_symbol(name)
        if sym is not None and sym.rebased_addr not in project._sim_procedures:
            project.hook(sym.rebased_addr, proc_cls())


# ---------------------------------------------------------------------------
# Fuzzer setup
# ---------------------------------------------------------------------------

def create_corpus():
    return [
        b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&y;</a>",  # one byte flip ('y'->'x') enables entity resolution path
    ]


def apply_fn(state: angr.SimState, data: bytes) -> None:
    # For entry_state with dynamically-linked binaries, do NOT call
    # cc.return_addr.set_value() — it overwrites [RSP] which is argc, not a
    # return address.  _ConcreteLibcStartMain already writes the exit
    # sentinel as main's return address, and the executor adds a breakpoint
    # at exit directly.
    s = state.posix.stdin
    s.content = [(claripy.BVV(data), claripy.BVV(len(data), state.arch.bits))]
    if hasattr(s, "pos"):
        s.pos = 0


# SEED VALUE NEEDED FOR TEST
def main(verbose=True, seed=12751):
    target = os.path.join(os.path.dirname(__file__), "xmllint_bin")

    # xmllint CLI: read from stdin with '-' and keep output quiet/nonet
    xmllint_args = [target, "--noout", "--nonet", "--recover", "--noent", "-"]

    project = angr.Project(target, auto_load_libs=True, use_sim_procedures=False)

    # With use_sim_procedures=False the loader still registers
    # IFuncResolvers for IFUNC symbols.  Remove them so icicle executes
    # the resolved implementations natively instead of round-tripping
    # through Python for every libc string call.
    from angr.procedures.linux_loader.sim_loader import IFuncResolver

    for addr, proc in list(project._sim_procedures.items()):
        if isinstance(proc, IFuncResolver):
            project.unhook(addr)

    # Set up concrete execution hooks before creating the fuzzer
    setup_concrete_hooks(project)

    # Eagerly resolve GOT entries — apply patches to the state after creation
    got_patches = resolve_got_entries(project)

    base_state = project.factory.entry_state(
        args=xmllint_args,
        add_options={
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
            so.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Apply GOT patches to the state
    for addr, data in got_patches.items():
        base_state.memory.store(addr, data)

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
        print(msg)

    before = len(fuzzer.corpus())
    idx = fuzzer.run_once(progress_callback=progress_callback if verbose else None)
    after = len(fuzzer.corpus())
    # take last mutation (should be the new one)
    new_input = fuzzer.corpus()[after - 1]
    if verbose:
        print(f"Corpus now has {len(fuzzer.corpus())} inputs.")
        print(f"Corpus inputs: \n{fuzzer.corpus().to_bytes_list()}")
        print(f"Found {len(fuzzer.solutions())} solutions.")
        print(f"Found the following solutions: \n{fuzzer.solutions().to_bytes_list()}")
    return idx, before, after, new_input


# @unittest.skip("disabled")
def test():
    idx, before, after, new_input = main(verbose=False)
    # Basic corpus growth sanity checks
    assert after == before + 1
    assert 0 <= idx < after

    # Desired mutation check: change entity reference '&y;' -> '&x;'
    expected = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>"
    assert new_input == expected
    return True


# looks for right seed to get deterministic answer
def search_for_seed():
    seed = 1
    expected = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>"
    while True:
        print(f"Attempting Seed: {seed}")
        _, _, _, new_input = main(verbose=False, seed=seed)
        if expected == new_input:
            print(f"Found Seed: {seed}")
            break
        seed += 1


if __name__ == "__main__":
    main()
