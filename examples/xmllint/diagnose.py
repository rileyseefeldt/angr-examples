#!/usr/bin/env python3
"""Diagnostic script to investigate slow icicle fuzzer execution on xmllint.

Replicates the exact setup from the fuzzer benchmark (auto_load_libs=True,
use_sim_procedures=False, UberIcicleEngine with snapshot mode and concrete
hooks) but instruments the emulator loop to log detailed timing and event
information for a single execution.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

import angr
import claripy
from angr import sim_options as so
from angr.emulator import Emulator, EmulatorStopReason, EngineException
from angr.engines.icicle import UberIcicleEngine
from solve import setup_concrete_hooks, resolve_got_entries

# ---------------------------------------------------------------------------
# Configuration (matches fuzzer_benchmark.py)
# ---------------------------------------------------------------------------
TARGET_PATH = os.path.join(os.path.dirname(__file__), "xmllint_bin")
TARGET_ARGS_SUFFIX = ["--noout", "--nonet", "--recover", "--noent", "-"]
SEED_INPUT = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&y;</a>"


# ---------------------------------------------------------------------------
# Per-step record
# ---------------------------------------------------------------------------
@dataclass
class StepRecord:
    step_num: int
    addr_before: int
    addr_after: int
    jumpkind: str
    instruction_count: int
    wall_seconds: float
    was_hook: bool = False
    hook_name: str | None = None
    was_syscall: bool = False
    syscall_info: str | None = None


@dataclass
class RunDiagnostics:
    steps: list[StepRecord] = field(default_factory=list)
    stop_reason: EmulatorStopReason | None = None
    total_wall_seconds: float = 0.0
    total_instructions: int = 0
    setup_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Instrumented emulator loop (replaces Emulator.run)
# ---------------------------------------------------------------------------
def instrumented_run(emu: Emulator, project: angr.Project, return_sentinel: int = 0) -> RunDiagnostics:
    """Run the emulator with full instrumentation, mirroring Emulator.run()."""
    diag = RunDiagnostics()
    engine = emu._engine
    state = emu._state
    breakpoints = emu._breakpoints

    completed_engine_execs = 0
    num_inst_executed = 0
    run_start = time.perf_counter()

    while state.history.jumpkind != "Ijk_Exit":
        # -- Breakpoint check (same logic as Emulator.run) --
        addr_cleared = state.addr & ~1
        if completed_engine_execs > 0 and addr_cleared in breakpoints:
            diag.stop_reason = EmulatorStopReason.BREAKPOINT
            break

        # -- Detect if this address is a hook or syscall --
        is_hook = False
        hook_name = None
        is_syscall = False
        syscall_info = None

        proc = project._sim_procedures.get(state.addr) or project._sim_procedures.get(state.addr & ~1)
        if proc is not None:
            is_hook = True
            hook_name = type(proc).__name__
            if hasattr(proc, 'display_name'):
                hook_name = proc.display_name

        if (state.history and state.history.parent
                and state.history.parent.jumpkind
                and state.history.parent.jumpkind.startswith("Ijk_Sys")):
            is_syscall = True
            try:
                sys_proc = project.simos.syscall(state)
                if sys_proc is not None:
                    syscall_info = f"{type(sys_proc).__name__}"
                    if hasattr(sys_proc, 'display_name'):
                        syscall_info = sys_proc.display_name
            except Exception:
                syscall_info = "<unknown>"

        # -- Continuation signal --
        if completed_engine_execs > 0 and hasattr(engine, "prepare_continuation"):
            engine.prepare_continuation()

        addr_before = state.addr
        step_start = time.perf_counter()

        # -- Engine step --
        try:
            successors = engine.process(state, extra_stop_points=breakpoints)
        except EngineException as exc:
            print(f"  !! EngineException at step {completed_engine_execs}: {exc}")
            raise

        step_elapsed = time.perf_counter() - step_start

        if len(successors.successors) == 0:
            diag.stop_reason = EmulatorStopReason.NO_SUCCESSORS
            rec = StepRecord(
                step_num=completed_engine_execs,
                addr_before=addr_before,
                addr_after=0,
                jumpkind="<no successors>",
                instruction_count=0,
                wall_seconds=step_elapsed,
                was_hook=is_hook,
                hook_name=hook_name,
                was_syscall=is_syscall,
                syscall_info=syscall_info,
            )
            diag.steps.append(rec)
            break

        state = successors.successors[0]
        emu._state = state  # keep emulator in sync

        icount = state.history.recent_instruction_count if state.history.recent_instruction_count > 0 else 0
        num_inst_executed += icount

        jk = state.history.jumpkind
        addr_after = state.addr

        rec = StepRecord(
            step_num=completed_engine_execs,
            addr_before=addr_before,
            addr_after=addr_after,
            jumpkind=jk,
            instruction_count=icount,
            wall_seconds=step_elapsed,
            was_hook=is_hook,
            hook_name=hook_name,
            was_syscall=is_syscall,
            syscall_info=syscall_info,
        )
        diag.steps.append(rec)

        # -- Print live progress --
        hook_tag = ""
        if is_hook:
            hook_tag = f" [HOOK: {hook_name}]"
        if is_syscall:
            hook_tag = f" [SYSCALL: {syscall_info}]"

        sym_before = describe_addr(project, addr_before, return_sentinel)
        sym_after = describe_addr(project, addr_after, return_sentinel)

        print(
            f"  step {completed_engine_execs:4d} | "
            f"0x{addr_before:x} ({sym_before}) -> 0x{addr_after:x} ({sym_after}) | "
            f"jk={jk:20s} | "
            f"icount={icount:>10,d} | "
            f"time={step_elapsed:8.4f}s"
            f"{hook_tag}"
        )

        # Early exit conditions
        if jk == "Ijk_EmFail":
            diag.stop_reason = EmulatorStopReason.EMULATION_GAP
            break

        if jk == "Ijk_SigSEGV":
            landed_addr = state.addr & ~1
            if landed_addr in breakpoints:
                diag.stop_reason = EmulatorStopReason.BREAKPOINT
            else:
                diag.stop_reason = EmulatorStopReason.MEMORY_ERROR
            break

        completed_engine_execs += 1

    run_elapsed = time.perf_counter() - run_start

    if diag.stop_reason is None:
        if state.history.jumpkind == "Ijk_Exit":
            diag.stop_reason = EmulatorStopReason.EXIT

    diag.total_wall_seconds = run_elapsed
    diag.total_instructions = num_inst_executed
    return diag


def describe_addr(project: angr.Project, addr: int, return_sentinel: int = 0) -> str:
    """Return a short symbolic description of an address."""
    if return_sentinel and (addr == return_sentinel or addr == (return_sentinel & ~1)):
        return "return_sentinel"
    try:
        return project.loader.describe_addr(addr)
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 80)
    print("XMLLINT ICICLE FUZZER DIAGNOSTIC")
    print("=" * 80)

    # -----------------------------------------------------------------------
    # Step 1: Project + state (identical to fuzzer_benchmark.py)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()

    target = os.path.abspath(TARGET_PATH)
    args = [target, *TARGET_ARGS_SUFFIX]

    print(f"\n[1] Loading project: {target}")
    project = angr.Project(target, auto_load_libs=True, use_sim_procedures=False)
    print(f"    arch={project.arch.name}  loader objects: {len(project.loader.all_objects)}")

    # Set up concrete execution hooks
    setup_concrete_hooks(project)
    got_patches = resolve_got_entries(project)

    # Resolve return sentinel from a mapped symbol (icicle needs mapped pages).
    exit_sym = project.loader.find_symbol("exit")
    if exit_sym is None:
        raise RuntimeError("Cannot find exit symbol for return sentinel")
    return_sentinel = exit_sym.rebased_addr

    print(f"\n[2] Creating entry state with args={args}")
    state = project.factory.entry_state(
        args=args,
        add_options={
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
            so.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Apply GOT patches
    for addr, data in got_patches.items():
        state.memory.store(addr, data)

    # -----------------------------------------------------------------------
    # Step 2: apply_fn (identical to benchmark)
    # -----------------------------------------------------------------------
    print(f"\n[3] Applying input ({len(SEED_INPUT)} bytes): {SEED_INPUT!r}")
    copied_state = state.copy()

    # Do NOT set the return address via cc.return_addr — for entry states it
    # overwrites [RSP] which is argc, not a return address.
    # _ConcreteLibcStartMain writes exit's address as main's return sentinel.
    print(f"    Return sentinel (exit): 0x{return_sentinel:X}")

    # Inject stdin
    copied_state.posix.stdin.content = [
        (claripy.BVV(SEED_INPUT), claripy.BVV(len(SEED_INPUT), copied_state.arch.bits))
    ]
    if hasattr(copied_state.posix.stdin, "pos"):
        copied_state.posix.stdin.pos = 0

    # -----------------------------------------------------------------------
    # Step 3: Create engine (identical to executor.rs)
    # -----------------------------------------------------------------------
    print("\n[4] Creating UberIcicleEngine with snapshot mode")
    engine = UberIcicleEngine(project)
    engine.enable_snapshot_mode()

    # Report registered hooks
    print(f"    Registered sim_procedures ({len(project._sim_procedures)}):")
    for addr, proc in sorted(project._sim_procedures.items()):
        name = type(proc).__name__
        if hasattr(proc, 'display_name'):
            name = proc.display_name
        sym_desc = describe_addr(project, addr, return_sentinel)
        print(f"      0x{addr:x}: {name} ({sym_desc})")

    # -----------------------------------------------------------------------
    # Step 4: Create Emulator + breakpoints (identical to executor.rs)
    # -----------------------------------------------------------------------
    print("\n[5] Creating Emulator and adding breakpoints")
    emulator = Emulator(engine, copied_state)
    emulator.add_breakpoint(return_sentinel)
    emulator.add_breakpoint(return_sentinel & ~1)
    print(f"    Breakpoints: {[hex(b) for b in sorted(emulator.breakpoints)]}")

    setup_time = time.perf_counter() - t0
    print(f"\n    Setup took {setup_time:.3f}s")

    # -----------------------------------------------------------------------
    # Step 5: Run with instrumentation
    # -----------------------------------------------------------------------
    print("\n[6] Running ONE execution (instrumented emulator loop)")
    print("-" * 120)

    diag = instrumented_run(emulator, project, return_sentinel)
    diag.setup_seconds = setup_time

    # -----------------------------------------------------------------------
    # Step 6: Summary
    # -----------------------------------------------------------------------
    print("-" * 120)
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"  Stop reason:           {diag.stop_reason}")
    print(f"  Total engine steps:    {len(diag.steps)}")
    print(f"  Total instructions:    {diag.total_instructions:,d}")
    print(f"  Total wall time:       {diag.total_wall_seconds:.4f}s")
    print(f"  Setup wall time:       {diag.setup_seconds:.4f}s")
    if diag.total_wall_seconds > 0:
        print(f"  Instructions/sec:      {diag.total_instructions / diag.total_wall_seconds:,.0f}")

    # Breakdown by step type
    hook_steps = [s for s in diag.steps if s.was_hook]
    syscall_steps = [s for s in diag.steps if s.was_syscall]
    native_steps = [s for s in diag.steps if not s.was_hook and not s.was_syscall]

    print(f"\n  Native (icicle) steps:  {len(native_steps)}")
    if native_steps:
        total_native_time = sum(s.wall_seconds for s in native_steps)
        total_native_inst = sum(s.instruction_count for s in native_steps)
        print(f"    Total time:          {total_native_time:.4f}s")
        print(f"    Total instructions:  {total_native_inst:,d}")
        if total_native_time > 0:
            print(f"    Avg time/step:       {total_native_time / len(native_steps):.6f}s")

    print(f"\n  Hook steps:             {len(hook_steps)}")
    if hook_steps:
        total_hook_time = sum(s.wall_seconds for s in hook_steps)
        print(f"    Total time:          {total_hook_time:.4f}s")
        if total_hook_time > 0:
            print(f"    Avg time/step:       {total_hook_time / len(hook_steps):.6f}s")
        # Group by hook name
        hook_counts: dict[str, int] = {}
        hook_times: dict[str, float] = {}
        for s in hook_steps:
            name = s.hook_name or "<unknown>"
            hook_counts[name] = hook_counts.get(name, 0) + 1
            hook_times[name] = hook_times.get(name, 0.0) + s.wall_seconds
        print("    By hook:")
        for name in sorted(hook_counts, key=lambda n: hook_times[n], reverse=True):
            print(f"      {name:40s} count={hook_counts[name]:5d}  time={hook_times[name]:.4f}s")

    print(f"\n  Syscall steps:          {len(syscall_steps)}")
    if syscall_steps:
        total_sys_time = sum(s.wall_seconds for s in syscall_steps)
        print(f"    Total time:          {total_sys_time:.4f}s")
        if total_sys_time > 0:
            print(f"    Avg time/step:       {total_sys_time / len(syscall_steps):.6f}s")
        # Group by syscall name
        sys_counts: dict[str, int] = {}
        sys_times: dict[str, float] = {}
        for s in syscall_steps:
            name = s.syscall_info or "<unknown>"
            sys_counts[name] = sys_counts.get(name, 0) + 1
            sys_times[name] = sys_times.get(name, 0.0) + s.wall_seconds
        print("    By syscall:")
        for name in sorted(sys_counts, key=lambda n: sys_times[n], reverse=True):
            print(f"      {name:40s} count={sys_counts[name]:5d}  time={sys_times[name]:.4f}s")

    # Top 20 slowest steps
    print("\n  Top 20 slowest steps:")
    for s in sorted(diag.steps, key=lambda s: s.wall_seconds, reverse=True)[:20]:
        tag = ""
        if s.was_hook:
            tag = f" [HOOK: {s.hook_name}]"
        if s.was_syscall:
            tag = f" [SYSCALL: {s.syscall_info}]"
        sym_before = describe_addr(project, s.addr_before, return_sentinel)
        print(
            f"    step {s.step_num:4d} | "
            f"0x{s.addr_before:x} ({sym_before}) | "
            f"jk={s.jumpkind:20s} | "
            f"icount={s.instruction_count:>10,d} | "
            f"time={s.wall_seconds:8.4f}s"
            f"{tag}"
        )

    # Jumpkind distribution
    jk_counts: dict[str, int] = {}
    jk_times: dict[str, float] = {}
    for s in diag.steps:
        jk_counts[s.jumpkind] = jk_counts.get(s.jumpkind, 0) + 1
        jk_times[s.jumpkind] = jk_times.get(s.jumpkind, 0.0) + s.wall_seconds
    print("\n  Jumpkind distribution:")
    for jk in sorted(jk_counts, key=lambda j: jk_times[j], reverse=True):
        print(f"    {jk:25s} count={jk_counts[jk]:5d}  time={jk_times[jk]:.4f}s")

    # Final state info
    final_state = emulator.state
    print(f"\n  Final PC:              0x{final_state.addr:x} ({describe_addr(project, final_state.addr, return_sentinel)})")
    print(f"  Final jumpkind:        {final_state.history.jumpkind}")

    print("\n" + "=" * 80)
    print("DONE")
    print("=" * 80)


if __name__ == "__main__":
    # Suppress noisy angr logging but keep warnings
    logging.getLogger("angr").setLevel(logging.WARNING)
    logging.getLogger("cle").setLevel(logging.WARNING)
    logging.getLogger("pyvex").setLevel(logging.WARNING)
    main()
