from __future__ import annotations

import os
from pathlib import Path
from threading import Lock
from typing import Any

import torch

from ml.next_action.model import NextActionGRU
from ml.next_action.vocabulary import token_id, token_name


DEFAULT_MODEL_PATH = Path("artifacts/next_action_hybrid/gru_hybrid_sentinel.pt")
MODEL_ENV = "SENTINEL_NEXT_ACTION_MODEL"

_MODEL = None
_MODEL_META = None
_MODEL_LOCK = Lock()


def _model_path() -> Path:
    raw = os.getenv(MODEL_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_MODEL_PATH


def _load_model():
    global _MODEL, _MODEL_META

    if _MODEL is not None:
        return _MODEL, _MODEL_META

    with _MODEL_LOCK:
        if _MODEL is not None:
            return _MODEL, _MODEL_META

        path = _model_path()
        if not path.exists():
            raise FileNotFoundError(f"GRU next-action model not found: {path}")

        checkpoint = torch.load(path, map_location="cpu")
        seq_len = int(checkpoint["seq_len"])
        vocab_size = int(checkpoint["vocab_size"])

        model = NextActionGRU(vocab_size=vocab_size)
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()

        _MODEL = model
        _MODEL_META = {
            "model_path": str(path),
            "seq_len": seq_len,
            "vocab_size": vocab_size,
        }
        return _MODEL, _MODEL_META


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def event_to_action(event) -> str:
    event_type = _norm(getattr(event, "event_type", None))
    process_name = _norm(getattr(event, "process_name", None))
    file_grade = _norm(getattr(event, "file_grade", None))
    file_access_count = int(getattr(event, "file_access_count", 0) or 0)
    usb_connected = bool(getattr(event, "usb_connected", False))

    explicit = {
        "login_success": "LOGIN_SUCCESS",
        "logon_success": "LOGIN_SUCCESS",
        "login_failure": "LOGIN_FAILURE",
        "login_failed": "LOGIN_FAILURE",
        "logon_failure": "LOGIN_FAILURE",
        "logoff": "LOGOFF",
        "logout": "LOGOFF",
        "usb_connect": "USB_CONNECT",
        "usb_connected": "USB_CONNECT",
        "usb_connection": "USB_CONNECT",
        "usb_activity": "USB_ACTIVITY",
        "usb_copy": "USB_COPY",
        "archive_create": "ARCHIVE_CREATE",
        "email_send": "EMAIL_SEND",
        "web_upload": "WEB_UPLOAD",
        "external_transfer": "EXTERNAL_TRANSFER",
        "network_access": "NETWORK_ACCESS",
        "privileged_logon": "PRIVILEGED_LOGON",
        "explicit_credential_logon": "EXPLICIT_CREDENTIAL_LOGON",
        "workstation_lock": "WORKSTATION_LOCK",
        "workstation_unlock": "WORKSTATION_UNLOCK",
        "auth_ticket": "AUTH_TICKET",
        "sensitive_file_access": "SENSITIVE_FILE_ACCESS",
        "mass_file_access": "MASS_FILE_ACCESS",
    }
    if event_type in explicit:
        return explicit[event_type]

    if event_type in {"process_execution", "process", "4688"} or process_name:
        pname = process_name.replace("\\", "/").rsplit("/", 1)[-1]
        if "powershell" in pname or pname == "pwsh.exe":
            return "POWERSHELL"
        if pname in {
            "cmd.exe", "cscript.exe", "wscript.exe", "mshta.exe",
            "rundll32.exe", "regsvr32.exe",
        }:
            return "SCRIPT_EXECUTION"
        if event_type in {"process_execution", "process", "4688"}:
            return "PROCESS_EXECUTION"

    if event_type in {"file_access", "document_analysis", "4663"}:
        if file_access_count >= 20:
            return "MASS_FILE_ACCESS"
        if any(
            marker in file_grade
            for marker in ("대외비", "기밀", "비밀", "confidential", "secret")
        ):
            return "SENSITIVE_FILE_ACCESS"
        return "FILE_ACCESS"

    if usb_connected:
        return "USB_CONNECT"

    return "OTHER"


def _event_payload(event, action: str) -> dict:
    ts = getattr(event, "timestamp", None)
    return {
        "id": getattr(event, "id", None),
        "timestamp": ts.isoformat() if ts is not None and hasattr(ts, "isoformat") else str(ts or ""),
        "event_type": getattr(event, "event_type", None),
        "process_name": getattr(event, "process_name", None),
        "action": action,
    }


@torch.no_grad()
def predict_actions(actions: list[str], top_k: int = 3) -> dict:
    model, meta = _load_model()
    seq_len = int(meta["seq_len"])

    normalized = [str(x).upper().strip() for x in actions if str(x).strip()]
    if len(normalized) < 3:
        return {
            "available": False,
            "reason": "최소 3개의 행동 이력이 필요합니다.",
            "sequence_length_required": seq_len,
            "sequence_length_used": len(normalized),
            "predictions": [],
        }

    normalized = normalized[-seq_len:]
    token_sequence = [token_id(x) for x in normalized]
    padded = [0] * (seq_len - len(token_sequence)) + token_sequence

    x = torch.tensor([padded], dtype=torch.long)
    probs = torch.softmax(model(x), dim=1)[0]

    k = min(max(int(top_k), 1), probs.numel())
    values, indices = torch.topk(probs, k=k)

    predictions = []
    for rank, (idx, prob) in enumerate(zip(indices.tolist(), values.tolist()), start=1):
        predictions.append({
            "rank": rank,
            "action": token_name(int(idx)),
            "probability": round(float(prob), 6),
            "probability_percent": round(float(prob) * 100.0, 2),
        })

    return {
        "available": True,
        "model": "GRU_NEXT_ACTION_HYBRID",
        "sequence_length_required": seq_len,
        "sequence_length_used": len(normalized),
        "input_actions": normalized,
        "predictions": predictions,
    }


def predict_next_actions_for_user(
    db,
    SecurityEvent,
    *,
    user: str,
    top_k: int = 3,
    reference_time=None,
    host: str | None = None,
    agent_id: str | None = None,
) -> dict:
    if not str(user or "").strip():
        return {"available": False, "reason": "user가 필요합니다.", "predictions": []}

    try:
        _, meta = _load_model()
        seq_len = int(meta["seq_len"])
    except Exception as exc:
        return {"available": False, "reason": str(exc), "predictions": []}

    query = db.query(SecurityEvent).filter(SecurityEvent.user == user)

    if host:
        query = query.filter(SecurityEvent.host == host)

    if agent_id:
        query = query.filter(SecurityEvent.agent_id == agent_id)

    if reference_time is not None:
        query = query.filter(SecurityEvent.timestamp <= reference_time)

    events = (
        query
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(max(seq_len * 4, 64))
        .all()
    )
    events = list(reversed(events))

    mapped = []
    for event in events:
        action = event_to_action(event)
        if action in {"PAD", "UNK", "OTHER"}:
            continue
        mapped.append((event, action))

    mapped = mapped[-seq_len:]
    actions = [action for _, action in mapped]

    result = predict_actions(actions, top_k=top_k)
    result["user"] = user
    result["host"] = host
    result["agent_id"] = agent_id
    result["recent_events"] = [_event_payload(event, action) for event, action in mapped]
    return result
