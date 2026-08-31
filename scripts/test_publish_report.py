#!/usr/bin/env python3
"""Regression tests for scripts/publish-report.sh.

These tests run the shell script with fake `rescope`, `aws`, and `date`
executables so the report key can be checked without touching AWS or the real
store. The invariant: a default publish key must be unique to the second, not a
whole UTC day, or a second scan of the same domain silently overwrites a client
citation.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "publish-report.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


def run_publish(*args: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        calls = root / "aws-calls.txt"

        write_executable(
            root / "rescope-fake",
            """#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$out" ] || { echo "missing -o" >&2; exit 1; }
printf '<html><title>fake report</title><code>seal</code></html>\n' > "$out"
""",
        )
        write_executable(
            bin_dir / "date",
            """#!/bin/sh
if [ "$1" = "-u" ] && [ "$2" = "+%Y%m%d-%H%M%S" ]; then
  echo 20260831-172713
  exit 0
fi
if [ "$1" = "-u" ] && [ "$2" = "+%Y%m%d" ]; then
  echo 20260831
  exit 0
fi
exec /bin/date "$@"
""",
        )
        write_executable(
            bin_dir / "aws",
            f"""#!/bin/sh
printf '%s\n' "$*" >> {calls}
if [ "$1" = "s3api" ] && [ "$2" = "put-object" ]; then
  case " $* " in
    *' --if-none-match * '*) exit 0 ;;
    *) echo 'missing --if-none-match' >&2; exit 1 ;;
  esac
fi
if [ "$1" = "cloudfront" ]; then
  echo INV123
fi
""",
        )

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{bin_dir}:{env['PATH']}",
                "RESCOPE": str(root / "rescope-fake"),
                "RS_S3_BUCKET": "rs-test-bucket",
                "RS_CF_DIST_ID": "DISTTEST",
            }
        )
        result = subprocess.run(
            ["bash", str(SCRIPT), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        return subprocess.CompletedProcess(
            result.args,
            result.returncode,
            stdout=f"{result.stdout}\nAWS_CALLS\n{calls.read_text()}",
            stderr=result.stderr,
        )


def assert_ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"publish-report failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_default_publish_key_uses_utc_second_stamp() -> None:
    result = run_publish("resolutionscope.com")
    assert_ok(result)
    assert "https://resolutionscope.com/r/resolutionscope.com/20260831-172713.html" in result.stdout


def test_explicit_publish_stamp_is_preserved() -> None:
    result = run_publish("resolutionscope.com", "manual-stamp")
    assert_ok(result)
    assert "https://resolutionscope.com/r/resolutionscope.com/manual-stamp.html" in result.stdout


def test_upload_refuses_to_overwrite_existing_report_key() -> None:
    result = run_publish("resolutionscope.com", "manual-stamp")
    assert_ok(result)
    assert "s3api put-object" in result.stdout
    assert "--if-none-match *" in result.stdout


if __name__ == "__main__":
    test_default_publish_key_uses_utc_second_stamp()
    test_explicit_publish_stamp_is_preserved()
    test_upload_refuses_to_overwrite_existing_report_key()
    print("publish-report tests passed")
