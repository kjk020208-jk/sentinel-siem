from __future__ import annotations

import argparse
import csv
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event

ROOT = Path(__file__).resolve().parent
DEFAULT_CSV = ROOT / "data" / "cert_r4.2" / "normalized_events.csv"


def as_int(value, default=0):
    try:
        return int(str(value or "").strip() or default)
    except ValueError:
        return default


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.strip())


def to_event(row: dict[str, str]) -> EventCreate:
    event_type = (row.get("event_type") or "").strip()
    usb_connected = as_int(row.get("usb_connected"), 0)

    # 프로젝트 내부에서 기존에 사용하던 event_type 명칭과 맞춘다.
    if event_type == "usb_connect":
        normalized_type = "usb_connected"
    elif event_type == "usb_disconnect":
        normalized_type = "usb_disconnected"
    else:
        normalized_type = event_type

    login_success = None
    if normalized_type == "login_success":
        login_success = 1

    return EventCreate(
        user=(row.get("user") or "").strip(),
        event_type=normalized_type,
        timestamp=parse_ts(row["timestamp"]),
        host=(row.get("host") or "").strip() or None,
        source=(row.get("source") or "cert_r4.2").strip(),
        raw_event_id=(row.get("raw_event_id") or "").strip() or None,
        source_ip=(row.get("source_ip") or "").strip() or None,
        login_success=login_success,
        login_fail_count=0,
        file_name=(row.get("file_name") or "").strip() or None,
        file_path=(row.get("file_path") or "").strip() or None,
        file_grade=None,
        file_access_count=as_int(row.get("file_access_count"), 0),
        usb_connected=usb_connected,
        device_name=(row.get("device_name") or "").strip() or None,
        device_id=(row.get("device_id") or "").strip() or None,
        process_name=(row.get("process_name") or "").strip() or None,
    )


def main():
    parser = argparse.ArgumentParser(description="CERT 공통 이벤트를 SENTINEL 분석 엔진으로 재생")
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--progress", type=int, default=1000)
    args = parser.parse_args()

    csv_path = args.csv.resolve()
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV가 없습니다: {csv_path}")

    db = SessionLocal()

    # CERT 대량 재생용 SQLite 튜닝.
    # 분석 로직/위험점수 계산은 바꾸지 않고 디스크 동기화 비용만 줄인다.
    try:
        db.execute(text("PRAGMA journal_mode=WAL"))
        db.execute(text("PRAGMA synchronous=NORMAL"))
        db.execute(text("PRAGMA temp_store=MEMORY"))
        db.execute(text("PRAGMA cache_size=-65536"))  # 약 64MB
        db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[WARN] SQLite 성능 설정 일부 적용 실패: {exc}")
    processed = 0
    failed = 0
    started = time.perf_counter()

    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row_no, row in enumerate(reader, start=2):
                if args.limit is not None and processed >= args.limit:
                    break

                try:
                    event = to_event(row)
                    if not event.user:
                        continue
                    process_security_event(event, db, perf_logging=False)
                    processed += 1
                except Exception as exc:
                    failed += 1
                    db.rollback()
                    print(f"[ERROR] {row_no}행: {exc}")

                if args.progress > 0 and processed and processed % args.progress == 0:
                    elapsed = time.perf_counter() - started
                    rate = processed / elapsed if elapsed else 0
                    print(f"[진행] {processed:,}건 | 실패 {failed:,}건 | {rate:,.1f}건/초")

        elapsed = time.perf_counter() - started
        print("\n[완료]")
        print(f"처리 성공: {processed:,}건")
        print(f"처리 실패: {failed:,}건")
        print(f"총 처리시간: {elapsed:,.2f}초")
        if elapsed:
            print(f"평균 처리속도: {processed / elapsed:,.1f}건/초")
    finally:
        db.close()


if __name__ == "__main__":
    main()
