#!/usr/bin/env python3
import asyncio
import time
import argparse
import sys
import statistics
import httpx
from tsa_benchmark import build_timestamp_request

async def run_burst(url: str, workers: int, duration: float = 5.0) -> tuple[int, int]:
    """Runs a short burst of requests with a fixed number of workers."""
    results = []
    deadline = time.monotonic() + duration
    
    async def worker():
        headers = {
            "Content-Type": "application/timestamp-query",
            "User-Agent": "TSA-Stress-Tester/1.0",
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=True) as client:
            while time.monotonic() < deadline:
                req_body = build_timestamp_request("sha256")
                try:
                    response = await client.post(url, content=req_body, headers=headers)
                    content_type = response.headers.get("content-type", "").lower()
                    if response.status_code == 200 and "application/timestamp-reply" in content_type:
                        results.append(True)
                    else:
                        results.append(False)
                except Exception:
                    results.append(False)

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await asyncio.gather(*tasks)
    
    total = len(results)
    successes = sum(1 for r in results if r)
    return successes, total

async def main():
    parser = argparse.ArgumentParser(description="Find the upper bound of a TSA endpoint's concurrency.")
    parser.add_argument("--url", default="http://tsa.example.com", help="TSA URL to test")
    parser.add_argument("--start-workers", type=int, default=10, help="Initial number of workers")
    parser.add_argument("--step", type=int, default=20, help="Worker increment per step")
    parser.add_argument("--max-workers", type=int, default=250, help="Maximum number of workers to test")
    parser.add_argument("--max-steps", type=int, help="Maximum number of steps to run (optional)")
    args = parser.parse_args()

    print("=" * 60)
    print(f"  TSA UPPER BOUND STRESS TEST")
    print("=" * 60)
    print(f"  Target URL: {args.url}")
    print(f"  Starting:   {args.start_workers} workers")
    print(f"  Increment:  {args.step} workers")
    print(f"  Max Cap:    {args.max_workers} workers")
    print("=" * 60)
    print("\n[!] WARNING: This may result in temporary IP banning if the TSA implements rate limiting.")
    print("    Press Ctrl+C at any time to stop.\n")

    current_workers = args.start_workers
    steps_run = 0
    last_stable_workers = 0

    try:
        while current_workers <= args.max_workers:
            if args.max_steps and steps_run >= args.max_steps:
                print(f"\nReached maximum configured steps ({args.max_steps}).")
                break

            print(f"▶ Testing {current_workers:>3} concurrent workers ... ", end="", flush=True)
            
            successes, total = await run_burst(args.url, current_workers)
            
            success_rate = (successes / total * 100) if total > 0 else 0
            
            print(f"Success Rate: {success_rate:>6.2f}% ({successes}/{total})")

            if success_rate < 100.0:
                print(f"\n[!] DROP OFF DETECTED at {current_workers} workers.")
                if last_stable_workers > 0:
                    print(f"    Confirmed upper bound for 100% success: {last_stable_workers} workers.")
                else:
                    print(f"    Initial load already failed. TSA might be heavily rate-limited or down.")
                break
            
            last_stable_workers = current_workers
            current_workers += args.step
            steps_run += 1
            
            # Small cooldown between bursts to be slightly "nicer"
            await asyncio.sleep(2)

        else:
            print(f"\nReached maximum worker cap ({args.max_workers}) with 100% success.")
            print(f"The upper bound is likely higher than {args.max_workers} concurrent workers.")

    except KeyboardInterrupt:
        print("\n\n⏹ Test interrupted by user.")
        if last_stable_workers > 0:
            print(f"Last stable worker count: {last_stable_workers}")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
