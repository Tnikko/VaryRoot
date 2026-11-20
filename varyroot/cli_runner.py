"""Route coordinator-launched CLI processes by their actual exit status."""
import json
import subprocess


SEMANTIC_FAILURES = {2: "invalid_bundle", 3: "invalid_ir", 4: "spec_conflict"}


class CliFailure(RuntimeError):
    def __init__(self, code, diagnostic, attempts):
        self.code = code
        self.diagnostic = diagnostic
        self.attempts = attempts
        self.retryable = code not in SEMANTIC_FAILURES
        super().__init__(f"CLI exit {code} on attempt {attempts}: {diagnostic}")


def _text(data):
    return data.decode(errors="replace") if isinstance(data, bytes) else data or ""


def _invoke(callback, argument, number):
    try:
        process = callback(argument)
    except subprocess.CalledProcessError as error:
        process = subprocess.CompletedProcess(error.cmd, error.returncode, error.stdout, error.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CliFailure(None, {"code": "launch_error", "message": str(error)}, number) from error
    if process.returncode == 0:
        return process
    try:
        diagnostic = json.loads(process.stdout or "")
        if not isinstance(diagnostic, dict):
            raise ValueError("expected diagnostic object")
    except (UnicodeError, ValueError):
        code = SEMANTIC_FAILURES.get(process.returncode, "infrastructure_failure")
        diagnostic = {"code": code, "stdout": _text(process.stdout), "stderr": _text(process.stderr)}
    raise CliFailure(process.returncode, diagnostic, number)


def run_cli(invoke, *, max_attempts=3):
    """Call invoke(number) with a fresh physical execution for each retry."""
    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("expected positive integer max_attempts")
    for number in range(1, max_attempts + 1):
        try:
            return _invoke(invoke, number, number)
        except CliFailure as error:
            if not error.retryable or number == max_attempts:
                raise


def _stdout(attempt, process):
    return json.loads(process.stdout)


def run_request(publication, request_id, invoke, output=_stdout):
    """Execute only reserved attempts, publishing success or fencing failure."""
    action = publication.recover(request_id)
    while action["action"] == "dispatch":
        attempt = action
        if not publication.claim(attempt):
            return {"action": "stale"}
        try:
            process = _invoke(invoke, attempt, attempt["attempt_id"])
            result = output(attempt, process)
            publication.submit(attempt, result)
        except CliFailure as error:
            action = publication.fail_attempt(
                attempt, {"exit_status": error.code, "result": error.diagnostic}, retryable=error.retryable)
        except OSError as error:
            action = publication.fail_attempt(attempt, {"code": "io_error", "message": str(error)}, retryable=True)
        except (ValueError, TypeError) as error:
            action = publication.fail_attempt(attempt, {"code": "invalid_result", "message": str(error)}, retryable=False)
        else:
            action = publication.recover(request_id)
    return action
