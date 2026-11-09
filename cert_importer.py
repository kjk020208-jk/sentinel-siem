from __future__ import annotations

import argparse
import csv
import heapq
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CERT_DIR = PROJECT_ROOT / "data" / "cert_r4.2"
DEFAULT_OUTPUT = DEFAULT_CERT_DIR / "normalized_events.csv"

OUTPUT_FIELDS = [
    "timestamp",
    "user",
    "event_type",
    "host",
    "source_ip",
    "process_name",
    "file_name",
    "file_path",
    "file_access_count",
    "usb_connected",
    "device_name",
    "device_id",
    "source",
    "raw_event_id",
]

# CERT r4.2의 일반적인 날짜 형식. 혹시 다른 미러에서 ISO 형식으로 제공해도 처리한다.
DATE_FORMATS = (
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)


def clean(value: Optional[str]) -> str:
    return (value or "").strip()


def get_value(row: Dict[str, str], *names: str) -> str:
    # 미러/전처리본에서 헤더 대소문자가 달라도 동작하도록 처리
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None:
            return clean(value)
    return ""


def parse_timestamp(value: str) -> datetime:
    value = clean(value)
    if not value:
        raise ValueError("날짜 값이 비어 있습니다.")

    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass

    # Python이 이해하는 ISO 변형은 마지막으로 한 번 더 시도
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"지원하지 않는 날짜 형식: {value}") from exc


def normalize_logon(row: Dict[str, str]) -> Dict[str, str]:
    activity = get_value(row, "activity", "action", "event")
    activity_lower = activity.lower()

    if "logoff" in activity_lower or "logout" in activity_lower:
        event_type = "logout"
    else:
        # CERT logon.csv의 Logon은 성공한 세션 시작 이벤트로 취급한다.
        event_type = "login_success"

    ts = parse_timestamp(get_value(row, "date", "timestamp", "time"))

    return {
        "timestamp": ts.isoformat(sep=" "),
        "user": get_value(row, "user", "username"),
        "event_type": event_type,
        "host": get_value(row, "pc", "host", "computer"),
        "source_ip": "",
        "process_name": "",
        "file_name": "",
        "file_path": "",
        "file_access_count": "0",
        "usb_connected": "0",
        "device_name": "",
        "device_id": "",
        "source": "cert_r4.2_logon",
        "raw_event_id": get_value(row, "id", "event_id"),
    }


def normalize_device(row: Dict[str, str]) -> Dict[str, str]:
    activity = get_value(row, "activity", "action", "event")
    activity_lower = activity.lower()
    connected = 0 if ("disconnect" in activity_lower or "remove" in activity_lower) else 1
    event_type = "usb_disconnect" if connected == 0 else "usb_connect"
    ts = parse_timestamp(get_value(row, "date", "timestamp", "time"))

    return {
        "timestamp": ts.isoformat(sep=" "),
        "user": get_value(row, "user", "username"),
        "event_type": event_type,
        "host": get_value(row, "pc", "host", "computer"),
        "source_ip": "",
        "process_name": "",
        "file_name": "",
        "file_path": "",
        "file_access_count": "0",
        "usb_connected": str(connected),
        "device_name": get_value(row, "device", "device_name"),
        "device_id": get_value(row, "device_id", "serial", "id"),
        "source": "cert_r4.2_device",
        "raw_event_id": get_value(row, "id", "event_id"),
    }


def normalize_file(row: Dict[str, str]) -> Dict[str, str]:
    file_path = get_value(row, "filename", "file", "file_path", "path")
    file_name = Path(file_path.replace("\\", "/")).name if file_path else ""
    ts = parse_timestamp(get_value(row, "date", "timestamp", "time"))

    return {
        "timestamp": ts.isoformat(sep=" "),
        "user": get_value(row, "user", "username"),
        "event_type": "file_access",
        "host": get_value(row, "pc", "host", "computer"),
        "source_ip": "",
        "process_name": "",
        "file_name": file_name,
        "file_path": file_path,
        "file_access_count": "1",
        "usb_connected": "0",
        "device_name": "",
        "device_id": "",
        "source": "cert_r4.2_file",
        "raw_event_id": get_value(row, "id", "event_id"),
    }


def validate_columns(path: Path, kind: str) -> None:
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)

    if not header:
        raise ValueError(f"{path.name}: 헤더가 없습니다.")

    normalized = {h.strip().lower() for h in header}
    required = {"date", "user", "pc"}
    missing = required - normalized
    if missing:
        raise ValueError(
            f"{path.name}: 필수 컬럼이 없습니다: {', '.join(sorted(missing))}\n"
            f"현재 헤더: {header}"
        )

    if kind == "logon" and "activity" not in normalized:
        raise ValueError(f"{path.name}: activity 컬럼이 없습니다. 현재 헤더: {header}")
    if kind == "device" and "activity" not in normalized:
        raise ValueError(f"{path.name}: activity 컬럼이 없습니다. 현재 헤더: {header}")
    if kind == "file" and not ({"filename", "file", "file_path", "path"} & normalized):
        raise ValueError(f"{path.name}: filename/file_path 계열 컬럼이 없습니다. 현재 헤더: {header}")


def read_normalized(path: Path, kind: str) -> Iterator[Dict[str, str]]:
    normalizer = {
        "logon": normalize_logon,
        "device": normalize_device,
        "file": normalize_file,
    }[kind]

    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        for line_no, row in enumerate(reader, start=2):
            try:
                item = normalizer(row)
                if not item["user"] or not item["timestamp"]:
                    continue
                yield item
            except Exception as exc:
                raise ValueError(f"{path.name} {line_no}행 변환 실패: {exc}") from exc


def write_sorted_chunk(rows: list[Dict[str, str]], temp_dir: Path, chunk_no: int) -> Path:
    rows.sort(key=lambda r: r["timestamp"])
    path = temp_dir / f"chunk_{chunk_no:05d}.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def chunk_iterator(path: Path) -> Iterator[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        yield from reader


def normalize_dataset(cert_dir: Path, output: Path, limit: Optional[int], chunk_size: int) -> int:
    sources = [
        (cert_dir / "logon.csv", "logon"),
        (cert_dir / "device.csv", "device"),
        (cert_dir / "file.csv", "file"),
    ]

    for path, kind in sources:
        if not path.exists():
            raise FileNotFoundError(f"필요한 파일이 없습니다: {path}")
        validate_columns(path, kind)

    output.parent.mkdir(parents=True, exist_ok=True)

    # 수백만 건도 메모리 폭주 없이 처리하기 위해 정렬된 임시 chunk를 만든 뒤 merge한다.
    with tempfile.TemporaryDirectory(prefix="cert_normalize_") as tmp:
        temp_dir = Path(tmp)
        chunk_paths: list[Path] = []
        buffer: list[Dict[str, str]] = []
        chunk_no = 0

        print("[1/3] CERT CSV 변환 중...")
        for path, kind in sources:
            print(f"  - {path.name}")
            for item in read_normalized(path, kind):
                buffer.append(item)
                if len(buffer) >= chunk_size:
                    chunk_paths.append(write_sorted_chunk(buffer, temp_dir, chunk_no))
                    chunk_no += 1
                    buffer = []

        if buffer:
            chunk_paths.append(write_sorted_chunk(buffer, temp_dir, chunk_no))

        print(f"[2/3] 시간순 병합 중... ({len(chunk_paths)}개 chunk)")
        iterators = [chunk_iterator(p) for p in chunk_paths]

        # heapq.merge는 각 iterator가 이미 정렬돼 있으므로 전체 파일을 메모리에 올리지 않는다.
        merged = heapq.merge(*iterators, key=lambda r: r["timestamp"])

        count = 0
        source_counts: Dict[str, int] = {}
        event_counts: Dict[str, int] = {}

        try:
            with output.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
                writer.writeheader()

                for row in merged:
                    writer.writerow(row)
                    count += 1
                    source_counts[row["source"]] = source_counts.get(row["source"], 0) + 1
                    event_counts[row["event_type"]] = event_counts.get(row["event_type"], 0) + 1

                    if limit is not None and count >= limit:
                        break
        finally:
            # Windows에서는 limit에 도달해 merge를 중간 종료하면
            # 각 chunk generator가 파일 핸들을 계속 잡고 있을 수 있다.
            # TemporaryDirectory 정리 전에 명시적으로 모두 닫는다.
            close_merged = getattr(merged, "close", None)
            if callable(close_merged):
                close_merged()
            for it in iterators:
                close_it = getattr(it, "close", None)
                if callable(close_it):
                    close_it()

    print("[3/3] 완료")
    print(f"출력 파일: {output}")
    print(f"총 이벤트: {count:,}건")
    print("이벤트 종류:")
    for key, value in sorted(event_counts.items()):
        print(f"  {key}: {value:,}")

    return count


def preview(cert_dir: Path) -> None:
    sources = [
        (cert_dir / "logon.csv", "logon"),
        (cert_dir / "device.csv", "device"),
        (cert_dir / "file.csv", "file"),
    ]
    for path, kind in sources:
        if not path.exists():
            print(f"[X] {path.name}: 없음")
            continue
        try:
            validate_columns(path, kind)
            size_mb = path.stat().st_size / 1024 / 1024
            print(f"[OK] {path.name}: {size_mb:.1f} MB")
            rows = read_normalized(path, kind)
            first = next(rows, None)
            if first:
                print(f"     예시: {first}")
        except Exception as exc:
            print(f"[ERROR] {path.name}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CERT r4.2 logon/device/file CSV를 SENTINEL 공통 이벤트 구조로 변환"
    )
    parser.add_argument(
        "--cert-dir",
        type=Path,
        default=DEFAULT_CERT_DIR,
        help="CERT r4.2 CSV 폴더 (기본: data/cert_r4.2)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="출력 CSV 경로",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="최종 출력 건수 제한. 예: --limit 100000",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=100_000,
        help="외부 정렬 chunk 크기 (기본 100000)",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="파일/헤더/샘플만 확인하고 종료",
    )
    args = parser.parse_args()

    cert_dir = args.cert_dir.resolve()
    output = args.output.resolve()

    if args.preview:
        preview(cert_dir)
        return

    normalize_dataset(cert_dir, output, args.limit, args.chunk_size)


if __name__ == "__main__":
    main()
