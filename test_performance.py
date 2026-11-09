import argparse
import statistics
import sys
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


API_URL = "http://127.0.0.1:8000"
TEST_USER = "__perf_verify__"
DEFAULT_SOURCE_IP = "198.51.100.25"


def ensure_test_user():
    """
    성능 테스트 전용 모니터링 사용자를 등록한다.
    이미 존재하면 그대로 사용한다.
    """
    try:
        response = requests.post(
            f"{API_URL}/users",
            json={
                "username": TEST_USER,
                "display_name": "Performance Test",
                "department": "TEST",
                "role": "PERF_TEST",
            },
            timeout=10,
        )

        if response.status_code == 200:
            print(f"[준비] 테스트 사용자 등록 완료: {TEST_USER}")
            return True

        if response.status_code == 409:
            print(f"[준비] 테스트 사용자 이미 존재: {TEST_USER}")

            enable_response = requests.post(
                f"{API_URL}/users/{TEST_USER}/enable",
                timeout=10,
            )

            if enable_response.status_code == 200:
                print("[준비] 테스트 사용자 모니터링 활성화 확인")
                return True

            print(
                "[오류] 테스트 사용자 활성화 실패:",
                enable_response.status_code,
                enable_response.text,
            )
            return False

        print(
            "[오류] 테스트 사용자 등록 실패:",
            response.status_code,
            response.text,
        )
        return False

    except requests.RequestException as error:
        print("[오류] FastAPI 연결 실패:", error)
        return False


def make_event(index, base_time):
    """
    일반적인 정상 프로세스 실행 이벤트를 생성한다.
    공격 시퀀스/Incident 성능이 아니라 전체 /events 분석 경로의
    처리량을 측정하는 목적이다.
    """
    process_names = [
        "notepad.exe",
        "calc.exe",
        "mspaint.exe",
        "explorer.exe",
    ]

    process_name = process_names[index % len(process_names)]

    return {
        "user": TEST_USER,
        "event_type": "process_execution",
        "timestamp": (
            base_time + timedelta(milliseconds=index)
        ).isoformat(),
        "host": "PERF-PC",
        "source": "performance_test",
        "raw_event_id": f"PERF-{index:08d}",
        "source_ip": DEFAULT_SOURCE_IP,
        "login_success": 1,
        "login_fail_count": 0,
        "file_access_count": 0,
        "usb_connected": 0,
        "process_name": process_name,
        "workstation_name": "PERF-PC",
        "logon_type": "2",
        "command_line": process_name,
        "parent_process": "explorer.exe",
    }


def post_one(index, base_time, timeout):
    started = time.perf_counter()

    try:
        response = requests.post(
            f"{API_URL}/events",
            json=make_event(index, base_time),
            timeout=timeout,
        )

        elapsed = time.perf_counter() - started

        return {
            "ok": response.status_code == 200,
            "status_code": response.status_code,
            "elapsed": elapsed,
            "error": (
                ""
                if response.status_code == 200
                else response.text[:300]
            ),
        }

    except requests.RequestException as error:
        elapsed = time.perf_counter() - started

        return {
            "ok": False,
            "status_code": None,
            "elapsed": elapsed,
            "error": str(error),
        }


def percentile(values, percentile_value):
    if not values:
        return 0.0

    sorted_values = sorted(values)

    if len(sorted_values) == 1:
        return sorted_values[0]

    rank = (
        percentile_value / 100.0
    ) * (len(sorted_values) - 1)

    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)

    weight = rank - lower

    return (
        sorted_values[lower] * (1 - weight)
        + sorted_values[upper] * weight
    )


def run_test(count, workers, timeout):
    print("=" * 80)
    print("SENTINEL 성능 테스트")
    print("=" * 80)
    print(f"API          : {API_URL}/events")
    print(f"사용자       : {TEST_USER}")
    print(f"이벤트 수    : {count:,}")
    print(f"동시 작업 수 : {workers}")
    print(f"Timeout      : {timeout}s")
    print("=" * 80)

    base_time = datetime.now()

    results = []
    total_started = time.perf_counter()

    if workers <= 1:
        for index in range(count):
            result = post_one(
                index=index,
                base_time=base_time,
                timeout=timeout,
            )
            results.append(result)

            current = index + 1

            if (
                current == count
                or current % max(1, count // 10) == 0
            ):
                success_so_far = sum(
                    1
                    for item in results
                    if item["ok"]
                )

                print(
                    f"[진행] {current:,}/{count:,} "
                    f"성공={success_so_far:,}"
                )

    else:
        with ThreadPoolExecutor(
            max_workers=workers
        ) as executor:

            futures = [
                executor.submit(
                    post_one,
                    index,
                    base_time,
                    timeout,
                )
                for index in range(count)
            ]

            completed = 0

            for future in as_completed(futures):
                results.append(future.result())
                completed += 1

                if (
                    completed == count
                    or completed % max(1, count // 10) == 0
                ):
                    success_so_far = sum(
                        1
                        for item in results
                        if item["ok"]
                    )

                    print(
                        f"[진행] {completed:,}/{count:,} "
                        f"성공={success_so_far:,}"
                    )

    total_elapsed = (
        time.perf_counter() - total_started
    )

    success_results = [
        item
        for item in results
        if item["ok"]
    ]

    failed_results = [
        item
        for item in results
        if not item["ok"]
    ]

    latencies = [
        item["elapsed"]
        for item in success_results
    ]

    success_count = len(success_results)
    failed_count = len(failed_results)

    throughput_eps = (
        success_count / total_elapsed
        if total_elapsed > 0
        else 0.0
    )

    average_latency = (
        statistics.mean(latencies)
        if latencies
        else 0.0
    )

    median_latency = (
        statistics.median(latencies)
        if latencies
        else 0.0
    )

    p95_latency = percentile(
        latencies,
        95,
    )

    p99_latency = percentile(
        latencies,
        99,
    )

    min_latency = min(
        latencies,
        default=0.0,
    )

    max_latency = max(
        latencies,
        default=0.0,
    )

    print()
    print("=" * 80)
    print("[성능 테스트 결과]")
    print("=" * 80)
    print(f"요청 이벤트 수    : {count:,}")
    print(f"성공              : {success_count:,}")
    print(f"실패              : {failed_count:,}")
    print(f"성공률            : {(success_count / count * 100 if count else 0):.2f}%")
    print(f"총 소요 시간      : {total_elapsed:.3f} sec")
    print(f"평균 처리량       : {throughput_eps:.2f} EPS")
    print(f"평균 응답 시간    : {average_latency * 1000:.2f} ms")
    print(f"중앙값 응답 시간  : {median_latency * 1000:.2f} ms")
    print(f"P95 응답 시간     : {p95_latency * 1000:.2f} ms")
    print(f"P99 응답 시간     : {p99_latency * 1000:.2f} ms")
    print(f"최소 응답 시간    : {min_latency * 1000:.2f} ms")
    print(f"최대 응답 시간    : {max_latency * 1000:.2f} ms")
    print("=" * 80)

    if failed_results:
        print()
        print("[실패 샘플 최대 5건]")

        for item in failed_results[:5]:
            print(
                f"- status={item['status_code']} "
                f"error={item['error']}"
            )

    print()
    print(
        "주의: 이 값은 현재 PC / SQLite / FastAPI / 전체 분석 파이프라인 "
        "환경에서 측정한 실측값입니다."
    )
    print(
        "      workers=1은 순차 end-to-end 처리량, workers>1은 "
        "동시 요청 부하 테스트입니다."
    )

    return failed_count == 0


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL /events end-to-end 성능 테스트"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="전송할 이벤트 수 (기본 1000)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="동시 요청 수 (기본 1)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="요청당 timeout 초 (기본 30)",
    )

    args = parser.parse_args()

    if args.count <= 0:
        print("[오류] --count는 1 이상이어야 합니다.")
        sys.exit(1)

    if args.workers <= 0:
        print("[오류] --workers는 1 이상이어야 합니다.")
        sys.exit(1)

    if not ensure_test_user():
        sys.exit(1)

    success = run_test(
        count=args.count,
        workers=args.workers,
        timeout=args.timeout,
    )

    sys.exit(
        0
        if success
        else 2
    )


if __name__ == "__main__":
    main()
