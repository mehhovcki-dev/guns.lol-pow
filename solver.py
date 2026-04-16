from __future__ import annotations
import base64, hashlib, multiprocessing as mp, os, sys, time
hex_chars = b"0123456789abcdef"

def _b64ud(s: str) -> bytes:
    s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return base64.b64decode(s)

def parse_challenge(o09_hex: str, _n: str, _org_ts: str, _2xa: str):
    blob = _b64ud(_2xa)
    if len(blob) < 3 or blob[0] != 0xA1 or blob[1] != 0x40:
        raise ValueError(f"bad _2xa magic: {blob[:2].hex() if len(blob) >= 2 else '<short>'}")

    dd = blob[2]
    if not (0 < dd <= 16):
        raise ValueError(f"invalid dd: {dd}")

    positions = sorted(blob[3 : 3 + dd])
    tmpl_off = 3 + 2 * dd + 8
    tmpl = blob[tmpl_off : tmpl_off + (64 - dd)]

    if len(_n) != 32 or len(_org_ts) != 10:
        raise ValueError(f"bad _n/_org_ts length: {len(_n)}/{len(_org_ts)}")

    seal = bytearray(64)
    t = 0
    pos_set = set(positions)
    for i in range(64):
        if i in pos_set:
            seal[i] = 0
        else:
            seal[i] = tmpl[t]
            t += 1

    suffix = (_n + _org_ts).encode("ascii")
    target = bytes.fromhex(o09_hex)
    if len(target) != 32:
        raise ValueError(f"o09 must be 64 hex chars, got {len(o09_hex)}")

    return dd, positions, bytes(seal), suffix, target

def _solve_range(args):
    seal_tmpl, positions, suffix, target, lo, hi = args
    dd = len(positions)
    seal = bytearray(seal_tmpl)
    sha256 = hashlib.sha256
    attempts = 0

    for n in range(lo, hi):
        attempts += 1
        v = n
        for k in range(dd):
            seal[positions[k]] = hex_chars[v & 0xF]
            v >>= 4
        if sha256(bytes(seal) + suffix).digest() == target:
            return bytes(seal), attempts
    return None, attempts

def _default_threads() -> int:
    env = os.environ.get("NATIVE_SOLVER_THREADS") or os.environ.get("OMP_NUM_THREADS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    cpu = os.cpu_count() or 1
    return max(1, cpu // 2)

def solve(o09: str, _n: str, _org_ts: str, _2xa: str, threads: int | None = None):
    dd, positions, seal_tmpl, suffix, target = parse_challenge(o09, _n, _org_ts, _2xa)
    total = 1 << (4 * dd)
    threads = threads or _default_threads()

    t0 = time.perf_counter()

    if threads == 1 or total <= 4096:
        seal, attempts = _solve_range((seal_tmpl, positions, suffix, target, 0, total))
        if seal is None:
            raise RuntimeError(f"no solution in 16^{dd} space")
        return seal, attempts, time.perf_counter() - t0

    per = (total + threads - 1) // threads
    ranges = [
        (seal_tmpl, positions, suffix, target, i * per, min((i + 1) * per, total))
        for i in range(threads)
    ]

    ctx = mp.get_context("fork") if sys.platform != "win32" else mp.get_context("spawn")
    total_attempts = 0
    winner = None
    with ctx.Pool(threads) as pool:
        for seal, attempts in pool.imap_unordered(_solve_range, ranges):
            total_attempts += attempts
            if seal is not None and winner is None:
                winner = seal
                pool.terminate()
                break

    if winner is None:
        raise RuntimeError(f"no solution in 16^{dd} space")
    return winner, total_attempts, time.perf_counter() - t0

def _usage():
    sys.stderr.write(f"usage: {sys.argv[0]} [bench N] <o09_hex> <_n> <_org_ts> <_2xa>\n")
    sys.exit(2)

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        _usage()

    bench = False
    N = 1
    argi = 1
    if argv[1] == "bench":
        if len(argv) < 7:
            _usage()
        bench = True
        N = int(argv[2])
        argi = 3

    if len(argv) - argi < 4:
        _usage()

    o09, _n, _ts, _2xa = argv[argi], argv[argi + 1], argv[argi + 2], argv[argi + 3]
    threads = _default_threads()

    if bench:
        sys.stderr.write(f"bench: {N} iterations on same challenge, {threads} threads\n")
        t0 = time.perf_counter()
        total_attempts = 0
        for _ in range(N):
            _seal, attempts, _dt = solve(o09, _n, _ts, _2xa, threads=threads)
            total_attempts += attempts
        elapsed = time.perf_counter() - t0
        rate = total_attempts / elapsed if elapsed > 0 else 0.0
        print(
            f"iterations={N} total_attempts={total_attempts} "
            f"elapsed={elapsed:.3f}s rate={rate / 1e6:.2f} MH/s "
            f"avg_time_per_solve={elapsed * 1000.0 / N:.3f}ms"
        )
        return 0

    seal, attempts, dt = solve(o09, _n, _ts, _2xa, threads=threads)
    rate = attempts / dt if dt > 0 else 0.0
    sys.stdout.buffer.write(seal)
    sys.stdout.write(f"\t{attempts}\t{rate:.0f}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (ValueError, RuntimeError) as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(1)
