"""Single pre-oracle provider call with immutable raw body recording."""

import hashlib
import json
import stat
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _write_once(path, data):
    path = Path(path)
    with path.open("xb") as stream:
        stream.write(data)


def _parse(raw, requested_model):
    try:
        payload = json.loads(raw)
        choice, = payload["choices"]
        finish = choice["finish_reason"]
        if finish == "length":
            return {"failure": "truncated"}, payload
        if finish != "stop" or choice["message"].get("tool_calls"):
            return {"failure": "unexpected_finish"}, payload
        if payload.get("model") not in (None, requested_model):
            return {"failure": "model_mismatch"}, payload
        content = json.loads(choice["message"]["content"])
        if not isinstance(content, dict) or not isinstance(content.get("proposals"), list):
            return {"failure": "invalid_proposal_envelope"}, payload
        return content, payload
    except (KeyError, ValueError, TypeError):
        return {"failure": "invalid_response"}, None


def post_once(request, output_dir, round_number, key_path, project_root, *,
              opener=None):
    """Save exact JSON request/response bodies; never persist the bearer key.

    The HTTPS library owns transport headers. The private Authorization header
    is intentionally absent from reproducible experiment artifacts.
    """
    key_path = Path(key_path).resolve(strict=True)
    root = Path(project_root).resolve()
    if key_path.is_relative_to(root) or stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise PermissionError("private_key_outside_project_required")
    key = key_path.read_text().strip()
    if not key.startswith("sk-") or "\n" in key:
        raise ValueError("invalid_private_key_shape")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"round-{round_number:02d}"
    if any((out / f"{stem}.{suffix}").exists() for suffix in
           ("request.json", "response.json", "meta.json")):
        raise FileExistsError(stem)
    body = _canonical(request)
    _write_once(out / f"{stem}.request.json", body)
    transport = opener or urllib.request.urlopen
    http_request = urllib.request.Request("https://api.deepseek.com/chat/completions", data=body,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                 "Accept": "application/json"}, method="POST")
    started = datetime.now(timezone.utc).isoformat()
    tick = time.monotonic()
    try:
        with transport(http_request, timeout=360) as response:
            raw, status = response.read(), response.status
            headers = dict(response.headers)
    except urllib.error.HTTPError as error:
        raw, status, headers = error.read(), error.code, dict(error.headers)
    except Exception as error:
        metadata = {"started_utc": started, "elapsed_s": round(time.monotonic() - tick, 3),
                    "status": "transport_failure", "error_type": type(error).__name__,
                    "request_sha256": hashlib.sha256(body).hexdigest()}
        _write_once(out / f"{stem}.meta.json", _canonical(metadata))
        return {"failure": "transport_failure"}
    _write_once(out / f"{stem}.response.json", raw)
    result, payload = _parse(raw, request["model"]) if status == 200 else (
        {"failure": "http_" + str(status)}, None)
    metadata = {"started_utc": started, "elapsed_s": round(time.monotonic() - tick, 3),
                "status": "valid_output" if "failure" not in result else result["failure"],
                "http_status": status, "response_headers": headers,
                "request_sha256": hashlib.sha256(body).hexdigest(),
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "response_model": payload.get("model") if payload else None,
                "finish_reason": payload["choices"][0].get("finish_reason")
                if payload and payload.get("choices") else None,
                "usage": payload.get("usage", {}) if payload else {}}
    _write_once(out / f"{stem}.meta.json", _canonical(metadata))
    return result
