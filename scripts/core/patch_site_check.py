"""Hotpatch-site safety validator for `REL::Relocation<...>::write_branch<N>` trampolines
(EngineFixesSkyrim64, and anything else that splices a jmp into live game code).

Run this in Ghidra BEFORE writing a trampoline patch. It cannot be checked from C++ at
patch-install time -- that only has the live bytes, not the disassembly/control-flow
picture needed to know whether some OTHER code path enters the range being overwritten.

## The rule

A `write_branch<N>` patch at `addr` is safe iff the overwritten range `[addr, addr+N)`
either:
  (a) lands exactly on instruction boundaries (consumes some whole number of complete
      instructions, nothing partial), or
  (b) ends INSIDE the same instruction it starts in (never reaches a second, distinct
      instruction at all).

It is UNSAFE the moment it fully consumes one instruction and then partially eats into
the next: that leaves live, non-instruction bytes sitting at an address that used to be
(and, to anything that jumps/calls there, still looks like) a real instruction's start.

## Why this rule, not an xref scan

The instinctive check is "does anything reference the address right after the last fully
covered instruction?" -- but that only catches entries Ghidra's xref analysis already
found (computed jumps, tail-shared code from identical-code-folding, etc. can all reach an
address with NO recorded xref). The boundary rule needs no xref knowledge at all: an
address is either the start of a pre-existing instruction (so ANYTHING could legitimately
target it, known or not) or it isn't. Never touch bytes at the start of an instruction you
don't fully own.

## Confirmed by an actual incident

EngineFixesSkyrim64's acoustic-space-listener null-rigidbody fix originally patched a
4-byte `mov rax,[rcx+0x10]` with a 5-byte jmp, borrowing the first byte of the following
`test rax,rax` -- case (a) violated, one instruction fully consumed plus 1 byte of a
second, distinct instruction. That byte turned out to be independently reachable and the
patch corrupted it into garbage, producing a WORSE crash on a live deploy
(crash-2026-07-19-21-26-33.log). The fix: relocate the patch site one instruction earlier,
to a 7-byte `mov rcx,[rax+0x128]` load, and re-run it plus the original faulting load
inside the trampoline -- case (b), ends inside the instruction it started in, never
reaches `test`.

## Usage

    from patch_site_check import check_write_branch
    ok, detail = check_write_branch(currentProgram, currentProgram.getAddressFactory().getAddress("1403eec8f"), 5)
    print(detail)
    assert ok, detail

Or from the Ghidra Script Manager / GhidrAssistMCP eval_python, point `ADDR`/`BRANCH_LEN`
at the candidate patch site and run this file directly for a printed verdict.
"""


def check_write_branch(program, addr, branch_len=5):
    """Check whether a `write_branch<branch_len>` patch at `addr` is safe.

    Returns (ok: bool, detail: str). `detail` always explains the verdict -- on failure,
    it names the instruction whose start address would be corrupted and how many callers
    the address boundary constraint alone (not xref-dependent) makes it unsafe to ignore.
    """
    listing = program.getListing()

    first = listing.getInstructionAt(addr)
    if first is None:
        return False, "no instruction at %s (undefined bytes / mid-instruction address)" % addr

    consumed = 0
    boundaries = []  # (instr_start_addr, instr_length)
    cur = first
    while consumed < branch_len:
        if cur is None:
            return False, "disassembly gap while walking from %s (ran out of instructions before covering %d bytes)" % (addr, branch_len)
        boundaries.append((cur.getAddress(), cur.getLength()))
        consumed += cur.getLength()
        cur = cur.getNext()

    if consumed == branch_len:
        return True, "safe: %d bytes cover exactly %d whole instruction(s), ends on a boundary" % (branch_len, len(boundaries))

    if len(boundaries) == 1:
        return True, ("safe: %d bytes end inside the single %d-byte instruction at %s "
                       "(never reaches a second instruction)") % (branch_len, boundaries[0][1], boundaries[0][0])

    # consumed > branch_len and more than one instruction touched: the LAST instruction in
    # `boundaries` is only partially overwritten -- its start address is a real, pre-existing
    # instruction boundary that anything could legitimately target.
    bad_addr, bad_len = boundaries[-1]
    overwritten = branch_len - (consumed - bad_len)
    return False, (
        "UNSAFE: %d-byte patch fully consumes %d instruction(s) then partially overwrites "
        "%d of %d bytes of the instruction at %s -- that address is a real instruction "
        "boundary anything could target, not just this patch's own trampoline. Relocate "
        "the patch site earlier (to a longer instruction that alone covers %d+ bytes), or "
        "extend the trampoline to re-run every instruction up to a boundary and choose "
        "%s as the resume point instead."
    ) % (branch_len, len(boundaries) - 1, overwritten, bad_len, bad_addr, branch_len, bad_addr)


def _main():
    # Fill these in when running interactively (Script Manager / eval_python), or import
    # check_write_branch() from another script instead.
    ADDR = None          # e.g. currentProgram.getAddressFactory().getAddress("1403eec8f")
    BRANCH_LEN = 5
    if ADDR is None:
        print("patch_site_check: set ADDR (and optionally BRANCH_LEN) before running, "
              "or import check_write_branch(program, addr, branch_len) from another script.")
        return
    ok, detail = check_write_branch(currentProgram, ADDR, BRANCH_LEN)  # noqa: F821
    print(("SAFE: " if ok else "UNSAFE: ") + detail)


if __name__ == '__main__':
    _main()
