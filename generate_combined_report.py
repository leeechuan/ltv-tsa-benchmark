#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from ltv_checker import PROVIDERS, generate_test_pki, run_benchmark, TSAResult
import tempfile
import shutil

async def generate_markdown_report(results: list[TSAResult], output_file: Path):
    """Generates a Markdown report from the benchmark results."""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# TSA LTV Compliance - Combined Report\n\n")
        f.write("| Status | TSA Provider | URL | Latency (ms) | LTV Passed | Validation Details |\n")
        f.write("| :---: | :--- | :--- | :---: | :---: | :--- |\n")
        for r in results:
            status_icon = "✅" if r.ltv_valid else "❌"
            ltv_text = "Yes" if r.ltv_valid else "No"
            details = r.validation_details.replace("; ", "<br>") if r.validation_details else (r.error or "N/A")
            provider_host = r.tsa_url.split('//')[1].split('/')[0] if '//' in r.tsa_url else r.tsa_url
            f.write(f"| {status_icon} | {provider_host} | {r.tsa_url} | {r.signing_latency_ms:.0f} | {ltv_text} | {details} |\n")

async def main():
    if not PROVIDERS:
        print("ERROR: No TSA providers configured in 'ltv_checker.py'.")
        print("Please edit 'ltv_checker.py' and add your TSA endpoints to the 'PROVIDERS' dictionary.")
        sys.exit(1)

    print(f"Generating combined report for {len(PROVIDERS)} TSA providers...")
    
    # Create artifacts directory for the report if it doesn't exist
    # (Actually, we should save it where the user can see it easily, or just in the project root)
    report_file = Path("combined_report.md")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="combined_report_"))
    try:
        pki = generate_test_pki(temp_dir)
        tsa_urls = list(PROVIDERS.values())
        
        results = await run_benchmark(
            tsa_urls=tsa_urls,
            pki=pki,
            iterations=1,
            verbose=True
        )
        
        await generate_markdown_report(results, report_file)
        print(f"\nReport generated: {report_file.absolute()}")
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(main())
