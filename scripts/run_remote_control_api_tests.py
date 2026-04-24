import io
import json
import importlib.util
import os
import pathlib
import socket
import sys
import time
import unittest


RESULTS_DIR = pathlib.Path(os.environ.get("RESULTS_DIR", "/results"))
REMOTE_SOCKET = os.environ.get("REMOTE_SOCKET", "/var/run/aminer-remote.socket")
WAIT_TIMEOUT_SECONDS = int(os.environ.get("WAIT_TIMEOUT_SECONDS", "120"))
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "1"))
TEST_FILE = pathlib.Path(os.environ.get("TEST_FILE", "unit/RemoteControlApiTest.py"))


def wait_for_unix_socket(timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(REMOTE_SOCKET)
            return
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        time.sleep(POLL_INTERVAL_SECONDS)
    raise TimeoutError(f"Timed out waiting for {REMOTE_SOCKET}")


def write_results(result: unittest.TestResult, log_output: str) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = RESULTS_DIR / "remote-control-api-test.log"
    summary_path = RESULTS_DIR / "remote-control-api-test-summary.json"

    log_path.write_text(log_output, encoding="utf-8")

    summary = {
        "testsRun": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "unexpectedSuccesses": len(getattr(result, "unexpectedSuccesses", [])),
        "expectedFailures": len(getattr(result, "expectedFailures", [])),
        "successful": result.wasSuccessful(),
        "remote_socket": REMOTE_SOCKET,
        "test_file": str(TEST_FILE),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def write_failure(message: str) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = RESULTS_DIR / "remote-control-api-test.log"
    summary_path = RESULTS_DIR / "remote-control-api-test-summary.json"

    log_path.write_text(f"{message}\n", encoding="utf-8")
    summary = {
        "successful": False,
        "error": message,
        "remote_socket": REMOTE_SOCKET,
        "test_file": str(TEST_FILE),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def load_test_suite() -> unittest.TestSuite:
    test_path = TEST_FILE.resolve()
    repo_root = test_path.parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    spec = importlib.util.spec_from_file_location("remote_control_api_test", test_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load test file from {test_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return unittest.defaultTestLoader.loadTestsFromModule(module)


def main() -> int:
    try:
        time.sleep(30)
        wait_for_unix_socket(WAIT_TIMEOUT_SECONDS)
        suite = load_test_suite()
        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        result = runner.run(suite)
        summary = write_results(result, stream.getvalue())
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if result.wasSuccessful() else 1
    except Exception as exc:
        summary = write_failure(f"{type(exc).__name__}: {exc}")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
