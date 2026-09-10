"""Build a byte-reproducible sdist and wheel from a clean checkout.

``setuptools`` honours ``SOURCE_DATE_EPOCH`` when it builds a wheel but not when
it builds an sdist, so this wrapper runs ``python -m build`` and then rewrites
every sdist tarball into a canonical form: members sorted by name, a fixed
mtime, no owner identity, normalised permissions, and a zeroed gzip header.
The result is identical byte-for-byte on every machine that checks out the same
commit with the same pinned build toolchain (see ``requirements/build.txt``).

Usage:

    python scripts/reproducible_build.py --outdir dist
    python scripts/reproducible_build.py --outdir dist --check   # build twice, compare hashes
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

_GZIP_OS_BYTE = 9
_GZIP_OS_UNKNOWN = 0xFF


def source_date_epoch() -> int:
    env = os.environ.get("SOURCE_DATE_EPOCH")
    if env:
        return int(env)
    out = subprocess.run(
        ["git", "log", "-1", "--pretty=%ct"],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return int(out.stdout.strip())


def _canonical_member(info: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    info.mtime = int(epoch)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    if info.isdir():
        info.mode = 0o755
    else:
        info.mode = 0o644
    return info


def normalize_sdist(path: Path, epoch: int) -> None:
    with tarfile.open(path, "r:gz") as tf:
        entries = sorted(tf.getmembers(), key=lambda m: m.name)
        payloads = {
            m.name: (tf.extractfile(m).read() if m.isreg() else None) for m in entries
        }

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for member in entries:
            info = _canonical_member(member, epoch)
            data = payloads[member.name]
            tf.addfile(info, io.BytesIO(data) if data is not None else None)

    compressed = bytearray(gzip.compress(raw.getvalue(), mtime=0))
    compressed[_GZIP_OS_BYTE] = _GZIP_OS_UNKNOWN
    path.write_bytes(bytes(compressed))


def build(outdir: Path, epoch: int) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(epoch), "PYTHONHASHSEED": "0"}
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(outdir)],
        cwd=_ROOT,
        check=True,
        env=env,
    )
    artifacts = sorted(outdir.iterdir())
    for artifact in artifacts:
        if artifact.name.endswith(".tar.gz"):
            normalize_sdist(artifact, epoch)
    return artifacts


def _hashes(paths: list[Path]) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="dist", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="build a second time into a temp dir and fail unless every hash matches",
    )
    args = parser.parse_args()

    epoch = source_date_epoch()
    print(f"SOURCE_DATE_EPOCH={epoch}")
    artifacts = build(args.outdir, epoch)
    digests = _hashes(artifacts)
    for name, digest in digests.items():
        print(f"{digest}  {name}")

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            rebuilt = build(Path(tmp), epoch)
            if _hashes(rebuilt) != digests:
                sys.exit("rebuild is not byte-identical; build is not reproducible")
        print("rebuild is byte-identical")


if __name__ == "__main__":
    main()
