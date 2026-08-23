#!/usr/bin/env python3
"""Deterministically mutate a local Tarsnap cachedir under ASan/UBSan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
from pathlib import Path

MARKERS = (
    b"AddressSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:",
    b"heap-use-after-free", b"stack-buffer-overflow", b"heap-buffer-overflow",
    b"double-free", b"SEGV", b"SIGABRT",
)
ASSERT_RE = re.compile(rb"(?:assertion|Assertion).*(?:failed|failure)", re.I)
CRASH_SIGS = {signal.SIGABRT, signal.SIGBUS, signal.SIGFPE,
              signal.SIGILL, signal.SIGSEGV, signal.SIGTRAP}


def run(binary: Path, keyfile: Path, cachedir: Path, sample: Path,
        initialize: bool, timeout: float, env: dict[str, str]):
    cmd = [str(binary), "--no-default-config", "--keyfile", str(keyfile),
           "--cachedir", str(cachedir)]
    if initialize:
        cmd.append("--initialize-cachedir")
    else:
        cmd += ["-c", "--dry-run", "--print-stats", str(sample)]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, env=env)


def crash(rc: int, err: bytes) -> tuple[bool, str | None]:
    name = None
    bad = any(x in err for x in MARKERS) or ASSERT_RE.search(err) is not None
    if rc < 0:
        try:
            sig = signal.Signals(-rc)
            name = sig.name
            bad |= sig in CRASH_SIGS
        except ValueError:
            name, bad = f"SIG{-rc}", True
    elif rc >= 128:
        try:
            sig = signal.Signals(rc - 128)
            if sig in CRASH_SIGS:
                name, bad = sig.name, True
        except ValueError:
            pass
    return bad, name


def files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def mutate(path: Path, peers: list[Path], rng: random.Random,
           iteration: int, max_size: int) -> str:
    data = path.read_bytes()
    mode = iteration % 14
    if mode == 0:
        n = rng.randrange(len(data) + 1)
        path.write_bytes(data[:n]); return f"truncate@{n}"
    if mode == 1:
        if data:
            a = rng.randrange(len(data)); b = rng.randrange(a, len(data) + 1)
            path.write_bytes(data[:a] + data[b:]); return f"delete[{a}:{b}]"
        path.write_bytes(b"X"); return "empty-to-byte"
    if mode == 2:
        d = bytearray(data or b"\0"); pos = []
        for _ in range(rng.randint(1, min(32, len(d)))):
            i = rng.randrange(len(d)); pos.append(i); d[i] ^= 1 << rng.randrange(8)
        path.write_bytes(d); return f"bitflip@{pos}"
    if mode == 3:
        i = rng.randrange(len(data) + 1); x = os.urandom(rng.randint(1, 512))
        path.write_bytes((data[:i] + x + data[i:])[:max_size]); return f"insert@{i}+{len(x)}"
    if mode == 4:
        n = rng.choice((1, 8, 16, 32, 64, 256, 4096, 65536))
        path.write_bytes(os.urandom(min(n, max_size))); return f"random-{min(n,max_size)}"
    if mode == 5:
        n = rng.choice((1, 8, 16, 64, 256, 4096, 65536))
        path.write_bytes((data + os.urandom(n))[:max_size]); return f"append-{n}"
    if mode == 6:
        path.write_bytes(b"\0" * min(max_size, rng.choice((1, 16, 256, 4096, 65536))))
        return "zero-fill"
    if mode == 7:
        path.write_bytes(b"\xff" * min(max_size, rng.choice((1, 16, 256, 4096, 65536))))
        return "ff-fill"
    if mode == 8:
        path.unlink(); return "delete-file"
    if mode == 9:
        path.unlink(); path.mkdir(); return "file-to-directory"
    if mode == 10:
        path.unlink(); path.symlink_to("/dev/null"); return "file-to-dev-null-symlink"
    if mode == 11:
        others = [p for p in peers if p != path and p.is_file()]
        if others:
            q = rng.choice(others); path.write_bytes(q.read_bytes()[:max_size])
            return f"replace-with-{q.name}"
        path.write_bytes(data[::-1]); return "reverse"
    if mode == 12:
        path.write_bytes(data[::-1]); return "reverse"
    d = bytearray(data or b"\0"); ops = rng.randint(2, 12)
    for _ in range(ops):
        if d and rng.randrange(3) == 0:
            d[rng.randrange(len(d))] = rng.randrange(256)
        elif rng.randrange(2) == 0:
            i = rng.randrange(len(d) + 1); d[i:i] = os.urandom(rng.randint(1, 64))
        elif d:
            a = rng.randrange(len(d)); b = rng.randrange(a, min(len(d), a + 128) + 1)
            del d[a:b]
    path.write_bytes(d[:max_size]); return f"mixed-{ops}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--keyfile", type=Path, required=True)
    ap.add_argument("--sample", type=Path, required=True)
    ap.add_argument("--iterations", type=int, default=2500)
    ap.add_argument("--random-seed", type=int, default=0x4341434845444952)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--max-size", type=int, default=262144)
    ap.add_argument("--output", type=Path, default=Path("cachedir-fuzz-out"))
    a = ap.parse_args()
    binary, keyfile, sample = a.binary.resolve(), a.keyfile.resolve(), a.sample.resolve()
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    for p in (binary, keyfile, sample):
        if not p.is_file(): raise SystemExit(f"missing input: {p}")
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=1:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    rng = random.Random(a.random_seed); findings = []; signatures = set()
    ok = rejected = timeouts = 0
    with tempfile.TemporaryDirectory(prefix="tarsnap-cachefuzz-") as td:
        root = Path(td); base = root / "base"; base.mkdir()
        r = run(binary, keyfile, base, sample, True, a.timeout, env)
        if r.returncode: (out / "init.stderr").write_bytes(r.stderr); return 1
        r = run(binary, keyfile, base, sample, False, a.timeout, env)
        if r.returncode: (out / "sanity.stderr").write_bytes(r.stderr); return 1
        rels = [p.relative_to(base) for p in files(base)]
        if not rels: raise SystemExit("cachedir has no regular files")
        baseline = [{"path": str(p), "size": (base/p).stat().st_size,
                     "sha256": hashlib.sha256((base/p).read_bytes()).hexdigest()} for p in rels]
        case = root / "case"
        for i in range(a.iterations):
            if case.exists(): shutil.rmtree(case)
            shutil.copytree(base, case, symlinks=True)
            rel = rels[i % len(rels)]; target = case / rel
            desc = mutate(target, [case/p for p in rels], rng, i, a.max_size)
            try:
                r = run(binary, keyfile, case, sample, False, a.timeout, env)
            except subprocess.TimeoutExpired as e:
                timeouts += 1; rc = None; sig = None
                err = (e.stderr or b"") + b"\nTIMEOUT\n"; bad = True
            else:
                rc, err = r.returncode, r.stderr; bad, sig = crash(rc, err)
                if not bad:
                    if rc == 0: ok += 1
                    else: rejected += 1
                    continue
            norm = re.sub(rb"0x[0-9a-fA-F]+", b"0xADDR", err[:8192])
            key = (sig, hashlib.sha256(norm).hexdigest())
            if key in signatures: continue
            signatures.add(key); n = len(findings)
            snap = out / f"finding-{n:02d}.tar.gz"
            with tarfile.open(snap, "w:gz") as t: t.add(case, arcname="cachedir")
            stderr_name = f"finding-{n:02d}.stderr"; (out/stderr_name).write_bytes(err)
            findings.append({"iteration": i, "target": str(rel), "mutation": desc,
                "returncode": rc, "signal": sig, "snapshot": snap.name,
                "stderr": stderr_name})
            if len(findings) >= 16: break
    summary = {"random_seed": a.random_seed, "iterations": a.iterations,
        "baseline_files": baseline, "successful": ok, "expected_rejections": rejected,
        "timeouts": timeouts, "unique_findings": len(findings), "findings": findings}
    (out/"summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    lines = ["# Tarsnap cachedir mutation probe", "",
        f"- Baseline files: {len(baseline)}", f"- Iterations: {a.iterations}",
        f"- Successful runs: {ok}", f"- Expected rejections: {rejected}",
        f"- Timeouts: {timeouts}", f"- Unique crash/hang signatures: **{len(findings)}**", ""]
    lines += [f"- `{x['path']}` — {x['size']} bytes — `{x['sha256']}`" for x in baseline]
    for x in findings:
        lines += ["", f"## {x['iteration']}: {x['mutation']}",
                  f"- Target: `{x['target']}`", f"- Return: `{x['returncode']}`",
                  f"- Signal: `{x['signal']}`", f"- Snapshot: `{x['snapshot']}`"]
    (out/"summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines)); return 2 if findings else 0


if __name__ == "__main__": raise SystemExit(main())
