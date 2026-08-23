#!/usr/bin/env python3
"""Deterministically mutate a Tarsnap keyfile and look for process crashes.

The probe is intentionally conservative: malformed-input rejection is expected and is
not reported. Only Unix crash signals, sanitizer diagnostics, or assertion failures are
saved as potential bounty candidates.
"""

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
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


CRASH_MARKERS = (
    b"AddressSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"runtime error:",
    b"heap-use-after-free",
    b"stack-buffer-overflow",
    b"heap-buffer-overflow",
    b"double-free",
    b"SEGV",
    b"SIGABRT",
)
ASSERTION_RE = re.compile(rb"(?:assertion|Assertion).*(?:failed|failure)", re.I)
CRASH_SIGNALS = {
    signal.SIGABRT,
    signal.SIGBUS,
    signal.SIGFPE,
    signal.SIGILL,
    signal.SIGSEGV,
    signal.SIGTRAP,
}


@dataclass(frozen=True)
class Finding:
    iteration: int
    mutation: str
    command_mode: str
    returncode: int
    signal_name: str | None
    input_sha256: str
    stderr_sha256: str
    input_file: str
    stderr_file: str


def bounded(blob: bytes, max_size: int) -> bytes:
    return blob[:max_size]


def mutate(seed: bytes, rng: random.Random, iteration: int, max_size: int) -> tuple[str, bytes]:
    mode = iteration % 12
    data = bytearray(seed)

    if mode == 0:
        cut = rng.randrange(0, len(data) + 1)
        return f"truncate@{cut}", bytes(data[:cut])

    if mode == 1 and data:
        start = rng.randrange(0, len(data))
        end = rng.randrange(start, len(data) + 1)
        del data[start:end]
        return f"delete[{start}:{end}]", bytes(data)

    if mode == 2 and data:
        count = rng.randint(1, min(16, len(data)))
        positions = []
        for _ in range(count):
            pos = rng.randrange(0, len(data))
            positions.append(pos)
            data[pos] ^= 1 << rng.randrange(0, 8)
        return f"bitflip@{positions}", bytes(data)

    if mode == 3:
        pos = rng.randrange(0, len(data) + 1)
        payload = bytes(rng.randrange(0, 256) for _ in range(rng.randint(1, 256)))
        data[pos:pos] = payload
        return f"insert-random@{pos}+{len(payload)}", bounded(bytes(data), max_size)

    if mode == 4 and data:
        start = rng.randrange(0, len(data))
        end = rng.randrange(start + 1, len(data) + 1)
        repeats = rng.randint(2, 16)
        pos = rng.randrange(0, len(data) + 1)
        data[pos:pos] = data[start:end] * repeats
        return (
            f"duplicate[{start}:{end}]x{repeats}@{pos}",
            bounded(bytes(data), max_size),
        )

    if mode == 5:
        lines = seed.splitlines(keepends=True)
        index = rng.randrange(0, max(1, len(lines)))
        width = rng.choice((1, 2, 3, 4, 63, 64, 65, 255, 256, 257, 4095, 4096, 4097, 65535))
        replacement = (rng.choice((b"A", b"/", b"=", b"0", b"z")) * width) + b"\n"
        if lines:
            lines[index] = replacement
        else:
            lines = [replacement]
        return f"replace-line-{index}-width-{width}", bounded(b"".join(lines), max_size)

    if mode == 6:
        lines = seed.splitlines(keepends=True)
        rng.shuffle(lines)
        return "shuffle-lines", bounded(b"".join(lines), max_size)

    if mode == 7:
        return "remove-newlines", bounded(seed.replace(b"\n", b""), max_size)

    if mode == 8:
        doubled = seed.replace(b"\n", b"\n\n")
        return "double-newlines", bounded(doubled, max_size)

    if mode == 9:
        prefix = bytes(rng.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") for _ in range(rng.randint(1, 8192)))
        return f"base64-prefix-{len(prefix)}", bounded(prefix + b"\n" + seed, max_size)

    if mode == 10:
        suffix = bytes(rng.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") for _ in range(rng.randint(1, 8192)))
        return f"base64-suffix-{len(suffix)}", bounded(seed + b"\n" + suffix + b"\n", max_size)

    # Multi-operation mutation, useful after the structured boundary cases above.
    operations = rng.randint(2, 8)
    for _ in range(operations):
        if not data or rng.random() < 0.4:
            pos = rng.randrange(0, len(data) + 1)
            payload = os.urandom(rng.randint(1, 64))
            data[pos:pos] = payload
        elif rng.random() < 0.5:
            pos = rng.randrange(0, len(data))
            data[pos] = rng.randrange(0, 256)
        else:
            start = rng.randrange(0, len(data))
            end = rng.randrange(start, min(len(data), start + 128) + 1)
            del data[start:end]
    return f"mixed-{operations}", bounded(bytes(data), max_size)


def classify(returncode: int, stderr: bytes) -> tuple[bool, str | None]:
    signal_name: str | None = None
    crashed = False

    if returncode < 0:
        sig_num = -returncode
        try:
            sig = signal.Signals(sig_num)
            signal_name = sig.name
            crashed = sig in CRASH_SIGNALS
        except ValueError:
            signal_name = f"SIG{sig_num}"
            crashed = True

    if returncode in {128 + int(sig) for sig in CRASH_SIGNALS}:
        sig_num = returncode - 128
        signal_name = signal.Signals(sig_num).name
        crashed = True

    if any(marker in stderr for marker in CRASH_MARKERS) or ASSERTION_RE.search(stderr):
        crashed = True

    return crashed, signal_name


def run_case(binary: Path, case_path: Path, mode: str, timeout: float, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    flag = "--print-key-id" if mode == "id" else "--print-key-permissions"
    return subprocess.run(
        [str(binary), flag, str(case_path)],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        env=env,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=2500)
    parser.add_argument("--random-seed", type=int, default=0x544152534E4150)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--max-size", type=int, default=262144)
    parser.add_argument("--output", type=Path, default=Path("keyfile-fuzz-out"))
    args = parser.parse_args()

    binary = args.binary.resolve()
    seed_path = args.seed.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    if not seed_path.is_file():
        raise SystemExit(f"seed not found: {seed_path}")

    seed = seed_path.read_bytes()
    rng = random.Random(args.random_seed)
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=1:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")

    # A valid seed must parse successfully, otherwise the campaign is not meaningful.
    sanity = run_case(binary, seed_path, "id", args.timeout, env)
    if sanity.returncode != 0:
        (output / "seed-sanity.stderr").write_bytes(sanity.stderr)
        raise SystemExit(f"seed sanity check failed with exit {sanity.returncode}")

    findings: list[Finding] = []
    signatures: set[tuple[str | None, str]] = set()
    timeouts = 0
    expected_rejections = 0

    with tempfile.TemporaryDirectory(prefix="tarsnap-keyfuzz-") as temp_dir:
        case_path = Path(temp_dir) / "case.keys"
        for iteration in range(args.iterations):
            mutation_name, case = mutate(seed, rng, iteration, args.max_size)
            case_path.write_bytes(case)
            command_mode = "id" if iteration % 2 == 0 else "permissions"

            try:
                result = run_case(binary, case_path, command_mode, args.timeout, env)
            except subprocess.TimeoutExpired:
                timeouts += 1
                continue

            crashed, signal_name = classify(result.returncode, result.stderr)
            if not crashed:
                if result.returncode != 0:
                    expected_rejections += 1
                continue

            stderr_digest = hashlib.sha256(result.stderr).hexdigest()
            normalized = re.sub(rb"0x[0-9a-fA-F]+", b"0xADDR", result.stderr[:8192])
            signature = (signal_name, hashlib.sha256(normalized).hexdigest())
            if signature in signatures:
                continue
            signatures.add(signature)

            index = len(findings)
            input_name = f"crash-{index:02d}.keys"
            stderr_name = f"crash-{index:02d}.stderr"
            shutil.copyfile(case_path, output / input_name)
            (output / stderr_name).write_bytes(result.stderr)
            finding = Finding(
                iteration=iteration,
                mutation=mutation_name,
                command_mode=command_mode,
                returncode=result.returncode,
                signal_name=signal_name,
                input_sha256=hashlib.sha256(case).hexdigest(),
                stderr_sha256=stderr_digest,
                input_file=input_name,
                stderr_file=stderr_name,
            )
            findings.append(finding)
            if len(findings) >= 16:
                break

    summary = {
        "binary": str(binary),
        "seed": str(seed_path),
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "random_seed": args.random_seed,
        "iterations_requested": args.iterations,
        "expected_rejections": expected_rejections,
        "timeouts": timeouts,
        "unique_crashes": len(findings),
        "findings": [asdict(item) for item in findings],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    markdown = [
        "# Tarsnap keyfile mutation probe",
        "",
        f"- Seed SHA-256: `{summary['seed_sha256']}`",
        f"- Deterministic random seed: `{args.random_seed}`",
        f"- Iterations requested: {args.iterations}",
        f"- Expected malformed-input rejections: {expected_rejections}",
        f"- Timeouts: {timeouts}",
        f"- Unique crash signatures: **{len(findings)}**",
        "",
    ]
    for item in findings:
        markdown.extend(
            [
                f"## Iteration {item.iteration}: {item.mutation}",
                "",
                f"- Mode: `{item.command_mode}`",
                f"- Return code: `{item.returncode}`",
                f"- Signal: `{item.signal_name}`",
                f"- Input: `{item.input_file}` (`{item.input_sha256}`)",
                f"- Stderr: `{item.stderr_file}` (`{item.stderr_sha256}`)",
                "",
            ]
        )
    (output / "summary.md").write_text("\n".join(markdown), encoding="utf-8")
    print("\n".join(markdown))

    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
