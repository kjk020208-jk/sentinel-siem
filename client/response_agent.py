import base64
import ctypes
import getpass
import io
import os
import socket
import subprocess
import time

import requests

API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000").rstrip("/")
POLL_SECONDS = float(os.getenv("SENTINEL_RESPONSE_POLL_SECONDS", "2"))
HOSTNAME = socket.gethostname()
USERNAME = getpass.getuser()


def is_windows():
    return os.name == "nt"


def is_admin():
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_active_window_title():
    if not is_windows():
        return ""
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(hwnd)
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        return buffer.value
    except Exception:
        return ""


def get_running_processes(limit=80):
    try:
        import psutil
        rows = []
        for p in psutil.process_iter(["pid", "name", "username"]):
            try:
                rows.append(dict(p.info))
            except Exception:
                continue
        rows.sort(key=lambda x: (str(x.get("name") or "").lower(), int(x.get("pid") or 0)))
        return rows[:limit]
    except Exception:
        pass

    if is_windows():
        try:
            import csv
            import io as _io
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            rows = []
            for item in csv.reader(_io.StringIO(result.stdout)):
                if len(item) >= 2:
                    rows.append({"name": item[0], "pid": item[1], "username": None})
            return rows[:limit]
        except Exception:
            return []
    return []


def capture_screen_base64():
    try:
        from PIL import ImageGrab
        image = ImageGrab.grab(all_screens=True)
        buf = io.BytesIO()
        image.save(buf, format="JPEG", quality=72, optimize=True)
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        pass

    try:
        import pyautogui
        image = pyautogui.screenshot()
        buf = io.BytesIO()
        image.save(buf, format="JPEG", quality=72)
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return None


def set_usb_write_restriction(enabled: bool):
    if not is_windows():
        return False, "Windows에서만 지원됩니다."
    if not is_admin():
        return False, "관리자 권한이 필요합니다. 관리자 권한 터미널에서 Agent를 실행하세요."

    try:
        import winreg
        path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.SetValueEx(
                key,
                "WriteProtect",
                0,
                winreg.REG_DWORD,
                1 if enabled else 0,
            )
        finally:
            winreg.CloseKey(key)

        state = "활성화" if enabled else "해제"
        return True, (
            f"USB 쓰기 제한 {state} 완료. "
            "이미 연결된 USB는 Windows 정책 적용 특성상 재연결이 필요할 수 있습니다."
        )
    except Exception as exc:
        return False, f"USB 쓰기 제한 처리 실패: {exc}"


def execute_action(action):
    action_type = str(action.get("action_type") or "").upper()
    operation = str(action.get("operation") or "").upper()

    if action_type == "USB_WRITE_RESTRICT":
        return set_usb_write_restriction(operation == "APPLY")

    return False, f"지원하지 않는 action_type: {action_type}"


def report_result(action, success, message, active_window, processes, screenshot_b64):
    payload = {
        "success": bool(success),
        "agent_message": message,
        "hostname": HOSTNAME,
        "username": USERNAME,
        "active_window": active_window,
        "running_processes": processes,
        "screenshot_base64": screenshot_b64,
    }
    r = requests.post(
        f"{API_URL}/response-controls/{action['id']}/result",
        json=payload,
        timeout=30,
    )
    r.raise_for_status()


def run_once():
    r = requests.post(
        f"{API_URL}/response-controls/claim",
        json={"hostname": HOSTNAME, "username": USERNAME},
        timeout=10,
    )
    r.raise_for_status()

    action = r.json().get("action")
    if not action:
        return False

    print()
    print("=" * 72)
    print(f"[SOAR] Action #{action['id']} {action['operation']} {action['action_type']}")
    print("=" * 72)

    active_window = get_active_window_title()
    processes = get_running_processes()
    screenshot_b64 = capture_screen_base64()

    success, message = execute_action(action)
    print("[SUCCESS]" if success else "[FAILED]", message)

    report_result(
        action,
        success,
        message,
        active_window,
        processes,
        screenshot_b64,
    )
    return True


def main():
    print("=" * 72)
    print("SENTINEL Windows Response Agent")
    print("=" * 72)
    print(f"API       : {API_URL}")
    print(f"Host      : {HOSTNAME}")
    print(f"User      : {USERNAME}")
    print(f"Admin     : {is_admin()}")
    print(f"Poll      : {POLL_SECONDS}s")
    print("Action    : USB_WRITE_RESTRICT")
    print("=" * 72)

    while True:
        try:
            handled = run_once()
            time.sleep(0.5 if handled else POLL_SECONDS)
        except KeyboardInterrupt:
            print("\nResponse Agent 종료")
            break
        except Exception as exc:
            print(f"[ERROR] {exc}")
            time.sleep(max(POLL_SECONDS, 2))


if __name__ == "__main__":
    main()
