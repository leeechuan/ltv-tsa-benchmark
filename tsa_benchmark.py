#!/usr/bin/env python3
"""
RFC 3161 TSA Benchmark POC
===========================
Benchmarks the performance and reliability of RFC 3161 Time Stamping Authority
endpoints (DigiCert, Entrust, or custom) under concurrent async load.

Usage examples:
  python tsa_benchmark.py --url https://tsa.example.com/ts --duration 60 --workers 5
  python tsa_benchmark.py --url https://tsa.example.com/ts --username user --password pass
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time
from dataclasses import dataclass, field

import httpx
from asn1crypto import algos, core, tsp

# ---------------------------------------------------------------------------
# Provider presets
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Provider presets
# ---------------------------------------------------------------------------
PROVIDERS: dict[str, dict[str, str]] = {
    # Add your proprietary or internal TSA endpoints here
    # "internal": {
    #     "url": "http://tsa.internal.example.com",
    #     "description": "Internal Corporate TSA",
    # },
}

# Mapping from friendly name → OID used in AlgorithmIdentifier
HASH_ALGORITHM_OIDS: dict[str, str] = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha1": "1.3.14.3.2.26",
}

# Hash digest lengths (bytes)
HASH_DIGEST_LENGTHS: dict[str, int] = {
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
    "sha1": 20,
}


# ---------------------------------------------------------------------------
# ASN.1 request builder
# ---------------------------------------------------------------------------
def build_timestamp_request(hash_algorithm: str = "sha256") -> bytes:
    """
    Construct a DER-encoded RFC 3161 TimeStampReq.

    The TimeStampReq ASN.1 structure (RFC 3161 §2.4.1):

        TimeStampReq ::= SEQUENCE {
            version        INTEGER  { v1(1) },
            messageImprint MessageImprint,
            reqPolicy      TSAPolicyId       OPTIONAL,
            nonce          INTEGER           OPTIONAL,
            certReq        BOOLEAN           DEFAULT FALSE,
            extensions     [0] IMPLICIT Extensions OPTIONAL
        }

        MessageImprint ::= SEQUENCE {
            hashAlgorithm  AlgorithmIdentifier,
            hashedMessage   OCTET STRING
        }

    We populate:
      - version = 1
      - messageImprint with the chosen hash algo OID and a random digest
      - nonce = random 8-byte integer (replay protection)
      - certReq = True (ask the TSA to include its signing certificate)

    Returns the raw DER bytes ready to POST.
    """
    algo = hash_algorithm.lower()
    if algo not in HASH_ALGORITHM_OIDS:
        raise ValueError(
            f"Unsupported hash algorithm '{algo}'. "
            f"Choose from: {', '.join(HASH_ALGORITHM_OIDS)}"
        )

    digest_length = HASH_DIGEST_LENGTHS[algo]
    random_hash = os.urandom(digest_length)

    # Build the AlgorithmIdentifier for the hash
    hash_algo_id = algos.DigestAlgorithmId(HASH_ALGORITHM_OIDS[algo])
    algorithm_identifier = algos.DigestAlgorithm({
        "algorithm": hash_algo_id,
    })

    # Build the MessageImprint
    message_imprint = tsp.MessageImprint({
        "hash_algorithm": algorithm_identifier,
        "hashed_message": core.OctetString(random_hash),
    })

    # Build the full TimeStampReq
    nonce = int.from_bytes(os.urandom(8), byteorder="big")

    ts_request = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": message_imprint,
        "nonce": nonce,
        "cert_req": True,
    })

    return ts_request.dump()


# ---------------------------------------------------------------------------
# Result collection
# ---------------------------------------------------------------------------
@dataclass
class RequestResult:
    success: bool
    latency_ms: float
    status_code: int | None = None
    error: str | None = None


@dataclass
class BenchmarkResults:
    results: list[RequestResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------
class RateLimiter:
    """Simple token-bucket style rate limiter for async tasks."""
    def __init__(self, requests_per_second: float):
        self.interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        """Wait until the next request is allowed."""
        async with self._lock:
            now = time.monotonic()
            wait_time = self.last_request_time + self.interval - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self.last_request_time = time.monotonic()
            else:
                self.last_request_time = now


# ---------------------------------------------------------------------------
# Async worker
# ---------------------------------------------------------------------------
async def worker(
    client: httpx.AsyncClient,
    url: str,
    hash_algorithm: str,
    deadline: float,
    results: list[RequestResult],
    worker_id: int,
    rate_limiter: RateLimiter | None = None,
    verbose: bool = False,
) -> None:
    """
    Continuously send timestamp requests until the deadline is reached.
    If a rate_limiter is provided, it controls the global cadence.
    Each iteration:
      1. Wait for rate limiter (if any)
      2. Build a fresh TimeStampReq (new random hash + nonce)
      3. POST it to the TSA URL
      4. Validate the response (HTTP 200 + correct Content-Type)
      5. Record latency and outcome
    """
    headers = {
        "Content-Type": "application/timestamp-query",
        "User-Agent": "TSA-Benchmark/1.0",
    }

    while time.monotonic() < deadline:
        if rate_limiter:
            await rate_limiter.wait()

        req_body = build_timestamp_request(hash_algorithm)
        t0 = time.monotonic()

        try:
            response = await client.post(url, content=req_body, headers=headers)
            latency_ms = (time.monotonic() - t0) * 1000

            content_type = response.headers.get("content-type", "").lower()
            is_ts_reply = "application/timestamp-reply" in content_type

            if response.status_code == 200 and is_ts_reply:
                result = RequestResult(
                    success=True,
                    latency_ms=latency_ms,
                    status_code=response.status_code,
                )
            else:
                reason = (
                    f"HTTP {response.status_code}"
                    if response.status_code != 200
                    else f"Unexpected Content-Type: {content_type}"
                )
                result = RequestResult(
                    success=False,
                    latency_ms=latency_ms,
                    status_code=response.status_code,
                    error=reason,
                )

            if verbose:
                tag = "✓" if result.success else "✗"
                print(
                    f"  [Worker {worker_id:>3}] {tag}  "
                    f"{latency_ms:>8.1f} ms  "
                    f"HTTP {response.status_code}  "
                    f"{content_type}"
                )

        except httpx.HTTPError as exc:
            latency_ms = (time.monotonic() - t0) * 1000
            result = RequestResult(
                success=False,
                latency_ms=latency_ms,
                error=str(exc),
            )
            if verbose:
                print(f"  [Worker {worker_id:>3}] ✗  {latency_ms:>8.1f} ms  ERROR: {exc}")

        results.append(result)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
async def run_benchmark(
    url: str,
    duration_seconds: int,
    concurrent_workers: int,
    hash_algorithm: str,
    max_rps: float | None = None,
    username: str | None = None,
    password: str | None = None,
    verbose: bool = False,
) -> BenchmarkResults:
    """Spawn concurrent workers and collect all results."""
    auth = None
    if username and password:
        auth = httpx.BasicAuth(username, password)

    # Use generous timeouts – some TSAs can be slow under load
    timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=30.0)

    limits = httpx.Limits(
        max_connections=concurrent_workers + 5,
        max_keepalive_connections=concurrent_workers,
    )

    rate_limiter = RateLimiter(max_rps) if max_rps and max_rps > 0 else None

    benchmark = BenchmarkResults()
    benchmark.start_time = time.monotonic()
    deadline = benchmark.start_time + duration_seconds

    async with httpx.AsyncClient(
        auth=auth,
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
    ) as client:
        tasks = [
            asyncio.create_task(
                worker(client, url, hash_algorithm, deadline, benchmark.results, i, rate_limiter, verbose)
            )
            for i in range(concurrent_workers)
        ]
        await asyncio.gather(*tasks)

    benchmark.end_time = time.monotonic()
    return benchmark


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(benchmark: BenchmarkResults, url: str) -> None:
    """Print a summary table of the benchmark run."""
    results = benchmark.results
    wall_time = benchmark.end_time - benchmark.start_time

    total = len(results)
    successes = sum(1 for r in results if r.success)
    failures = total - successes
    success_rate = (successes / total * 100) if total else 0.0

    latencies = [r.latency_ms for r in results]
    success_latencies = [r.latency_ms for r in results if r.success]

    avg_latency = statistics.mean(latencies) if latencies else 0.0
    p95_latency = (
        sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0.0
    )
    throughput = total / wall_time if wall_time > 0 else 0.0

    avg_success_latency = statistics.mean(success_latencies) if success_latencies else 0.0
    p95_success_latency = (
        sorted(success_latencies)[int(len(success_latencies) * 0.95)]
        if success_latencies
        else 0.0
    )

    separator = "─" * 56
    print()
    print(f"┌{separator}┐")
    print(f"│{'RFC 3161 TSA BENCHMARK REPORT':^56}│")
    print(f"├{separator}┤")
    print(f"│  Endpoint:  {url:<42}│")
    print(f"│  Duration:  {wall_time:<42.2f}│")
    print(f"├{separator}┤")
    print(f"│  {'Metric':<36} {'Value':>16} │")
    print(f"├{separator}┤")
    print(f"│  {'Total Requests':<36} {total:>16,} │")
    print(f"│  {'Successful':<36} {successes:>16,} │")
    print(f"│  {'Failed':<36} {failures:>16,} │")
    print(f"│  {'Success Rate':<36} {success_rate:>15.1f}% │")
    print(f"├{separator}┤")
    print(f"│  {'Avg Latency (all, ms)':<36} {avg_latency:>16.1f} │")
    print(f"│  {'P95 Latency (all, ms)':<36} {p95_latency:>16.1f} │")
    print(f"│  {'Avg Latency (success, ms)':<36} {avg_success_latency:>16.1f} │")
    print(f"│  {'P95 Latency (success, ms)':<36} {p95_success_latency:>16.1f} │")
    print(f"├{separator}┤")
    print(f"│  {'Throughput (req/s)':<36} {throughput:>16.2f} │")
    print(f"└{separator}┘")

    # Show a sample of errors if any
    errors = [r for r in results if not r.success]
    if errors:
        print(f"\n⚠  Sample errors (showing up to 5 of {len(errors)}):")
        for r in errors[:5]:
            print(f"   • {r.error}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RFC 3161 TSA Benchmark — measure timestamp authority performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://tsa.example.com --duration 15 --workers 5
  %(prog)s --url https://tsa.example.com --username myuser --password mypass
        """,
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--provider",
        choices=list(PROVIDERS.keys()),
        help="Use a preset TSA provider (digicert, entrust)",
    )
    target.add_argument(
        "--url",
        help="Custom TSA endpoint URL",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        metavar="SEC",
        help="Test duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        metavar="N",
        help="Number of concurrent workers (default: 10)",
    )
    parser.add_argument(
        "--rps",
        type=float,
        metavar="N",
        help="Target requests per second across all workers (optional, e.g. 5)",
    )
    parser.add_argument(
        "--hash-algo",
        default="sha256",
        choices=list(HASH_ALGORITHM_OIDS.keys()),
        help="Hash algorithm for the timestamp request (default: sha256)",
    )
    parser.add_argument(
        "--username",
        help="Username for HTTP Basic Auth (optional)",
    )
    parser.add_argument(
        "--password",
        help="Password for HTTP Basic Auth (optional)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each request result as it completes",
    )

    return parser.parse_args()


async def async_main() -> None:
    args = parse_args()

    # Resolve the target URL
    if args.provider:
        preset = PROVIDERS[args.provider]
        url = preset["url"]
        provider_label = f"{args.provider.title()} ({preset['description']})"
    else:
        url = args.url
        provider_label = url

    print()
    print("=" * 60)
    print("  RFC 3161 TSA Benchmark")
    print("=" * 60)
    print(f"  Target:     {provider_label}")
    print(f"  URL:        {url}")
    print(f"  Duration:   {args.duration}s")
    print(f"  Workers:    {args.workers}")
    print(f"  Hash Algo:  {args.hash_algo}")
    print(f"  Auth:       {'Basic Auth' if args.username else 'None'}")
    print("=" * 60)
    print()
    print("▶  Running benchmark …")

    benchmark = await run_benchmark(
        url=url,
        duration_seconds=args.duration,
        concurrent_workers=args.workers,
        hash_algorithm=args.hash_algo,
        max_rps=args.rps,
        username=args.username,
        password=args.password,
        verbose=args.verbose,
    )

    print_report(benchmark, url)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n\n⏹  Benchmark interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
