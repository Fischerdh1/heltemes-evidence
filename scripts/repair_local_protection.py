"""User-operated, narrowly scoped startup repair with private diagnostic capture."""
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import webbrowser
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
DASHBOARD = "http://127.0.0.1:8765"


def confirmed_success(result):
    """A zero exit alone never establishes that activation was proved."""
    return (isinstance(result, dict) and result.get("ok") is True
            and result.get("dashboard_started") is True
            and result.get("installation_report_written") is True
            and isinstance(result.get("dashboard"), dict)
            and result["dashboard"].get("managed_health_confirmed") is True)


def main():
    try:
        spec = importlib.util.spec_from_file_location("repair_log_helper", ROOT / "scripts/activate_local_accounts.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        path, log = helper.open_diagnostic_log()
    except (OSError, ValueError, ImportError) as error:
        print("Repair stopped before authentication: " + str(error), file=sys.stderr)
        return 1
    with log:
        def emit(message):
            # Persist first: a closed Terminal must not erase an interruption
            # message merely because its stdout pipe is no longer writable.
            log.write(message + "\n")
            log.flush()
            try:
                print(message, flush=True)
            except (BrokenPipeError, OSError):
                pass

        def interrupted(signum, frame):
            raise InterruptedError("Received signal " + str(signum))

        previous_signals = {}
        verified = False
        try:
            for name in ("SIGHUP", "SIGTERM"):
                number = getattr(signal, name, None)
                if number is not None:
                    previous_signals[number] = signal.signal(number, interrupted)
            emit("HELTEMES Evidence — Startup repair 1")
            emit("Attempt time (UTC): " + datetime.now(timezone.utc).isoformat())
            emit("Repair status: INCOMPLETE until verified success is recorded below.")
            emit("Fix writing to the two existing dashboard log files; keep their parent folder protected.")
            emit("Check the existing accounts and preserved archive, start the collector, and save the verified installation report.")
            emit("This repair preserves filings, signing identity, and accepted trust history. AWS remains deferred.")
            emit("Administrator authentication goes directly to macOS and is not recorded.")
            emit("Diagnostic log: " + str(path))
            authentication = subprocess.run(["/usr/bin/sudo", "-v"], check=False)
            if authentication.returncode:
                emit("Authentication did not complete; the repair helper was not started.")
                emit("Repair status: NOT COMPLETED.")
                return authentication.returncode
            emit("Authentication completed. Running the guarded startup repair; keep this window open.")
            result = subprocess.run(
                ["/usr/bin/sudo", "-n", "--", RUNTIME, "-I", "-S", "-B",
                 str(ROOT / "scripts/repair_local_startup.py")],
                check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, errors="replace")
            if result.stdout:
                emit(result.stdout.rstrip("\n"))
            emit("Repair helper exit status: " + str(result.returncode))
            if result.returncode:
                emit("Repair status: NOT CONFIRMED. The exact helper result is saved; inspect it before retrying.")
                return result.returncode
            try:
                evidence = json.loads(result.stdout)
            except (ValueError, TypeError):
                evidence = None
            if not confirmed_success(evidence):
                emit("Repair status: NOT CONFIRMED. A complete verified success result was not returned; the browser was not opened.")
                return 1
            verified = True
            emit("Repair status: COMPLETE. The managed listener and saved installation report were confirmed.")
            emit("Opening the managed dashboard: " + DASHBOARD)
            try:
                opened = webbrowser.open(DASHBOARD)
            except (OSError, webbrowser.Error) as error:
                emit("The repair passed, but the browser could not open: " + str(error))
            else:
                if not opened:
                    emit("The repair passed. Open the dashboard address above manually.")
            return 0
        except (KeyboardInterrupt, InterruptedError) as error:
            if verified:
                emit("Repair remains COMPLETE. Opening the browser was interrupted after verification passed.")
                return 0
            emit("Repair status: INTERRUPTED; completion was not confirmed. Inspect the saved state before retrying.")
            emit("Interruption: " + (str(error) or "Terminal interruption"))
            return 130
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            emit("Repair status: NOT CONFIRMED. Repair stopped: " + str(error))
            return 1
        finally:
            for number, handler in previous_signals.items():
                signal.signal(number, handler)
            emit("Diagnostic log: " + str(path))


if __name__ == "__main__":
    raise SystemExit(main())
