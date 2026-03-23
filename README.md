# LTV Checker and TSA Benchmark

This project provides tools to benchmark RFC 3161 Time Stamping Authority (TSA) endpoints and verify their ability to produce Long-Term Validation (LTV) compliant PDF signatures (PAdES B-LTA).

## Overview

The repository contains five main utilities:
1. **`ltv_checker.py`**: End-to-end PDF signing tool with strict LTV validation.
2. **`generate_combined_report.py`**: Automates testing of all preset TSAs and generates a combined Markdown report.
3. **`tsa_benchmark.py`**: Loads testing script for raw HTTP/TSA latency and throughput.
4. **`find_upper_bound.py`**: Stress tester to identify the concurrency limit where a TSA's success rate begins to drop.
5. **`e2e_benchmark.py`**: Combined load tester for the full archival validity chain.

## Setup

1. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

All tools require an RFC 3161 TSA endpoint URL. Use public discovery or your company's internal TSA URL.

### 1. Functional LTV Verification (`ltv_checker.py`)
This tool checks for **LTV (Long-Term Validation)** compliance by signing a test PDF, embedding revocation info (CRL/OCSP), adding a Document Timestamp, and then performing a strict PAdES B-LTA validation.

```powershell
# Basic test with a mandatory 2-second delay between providers/iterations
python ltv_checker.py --tsa https://tsa.example.com --delay 2 -v

# Run 3 sequential iterations to confirm stability
python ltv_checker.py --tsa https://tsa.example.com --iterations 3 --delay 1
```

### 2. Performance Benchmark (`tsa_benchmark.py`)
Measures raw TSA response speed and throughput under concurrent load. Designed for high-concurrency testing.

```powershell
# Run a 30s benchmark with 10 concurrent workers, limited to 5 requests per second
python tsa_benchmark.py --url https://tsa.example.com --duration 30 --workers 10 --rps 5
```

### 3. Load & Reliability Test (`e2e_benchmark.py`)
Similar to `tsa_benchmark`, but performs the **full PDF signing and LTV verification pipeline** for every request. This is the most resource-intensive test.

```powershell
# 10s load test with 5 workers at a controlled 1 request per second
python e2e_benchmark.py --tsa https://tsa.example.com --duration 10 --workers 5 --rps 1
```

### 4. Stress Testing & Limit Discovery (`find_upper_bound.py`)
Identifies the point of failure for a TSA endpoint by progressively increasing concurrency.

```powershell
python find_upper_bound.py --url https://tsa.example.com --start-workers 5 --step 5 --max-workers 50
```

---

## 🛠️ Configuration and Customization

### Configuring Private Presets
To use your internal TSA endpoints with shorthand names (like presets), edit the `PROVIDERS` dictionary in `ltv_checker.py`:

```python
# ltv_checker.py
PROVIDERS = {
    "my-internal-tsa": "https://tsa.internal.mycompany.com",
}
```

Then you can use `--preset`:
```powershell
python ltv_checker.py --preset my-internal-tsa
```

### Custom Trust Roots
If a private or internal TSA uses a custom Root CA:
1.  Save the Root CA certificate as a `.pem` file in the `certs/` directory.
2.  The validation engine will automatically load it as a trusted root.

---

---

## ⚖️ Legal Disclaimer & Responsible Use

### Responsible Testing
This project is for **benchmarking and educational** purposes. Public Time Stamping Authorities (TSAs) provide essential security services for the ecosystem, and their capacity is shared across all users.

*   **Respect Rate Limits:** Most public TSAs enforce rate limits (e.g., 5-10 requests per second).
*   **Adhere to ToS:** Always review and comply with the Terms of Service of your TSA provider.
*   **Abuse Policy:** High-volume traffic can be flagged as a DDoS attack. Use the built-in rate limiting features below to stay within bounds.

### Rate Limiting by Design
For responsible use of the public PKI, all tools include built-in rate limiting:
*   **`--rps N`**: In `tsa_benchmark.py` and `e2e_benchmark.py`, this limits total requests across all concurrent workers to `N` per second.
*   **`--delay SEC`**: In `ltv_checker.py`, this adds a mandatory `SEC` second wait between sequential signing attempts.

**Recommended Defaults:**
- **General Testing:** Start with 1-2 workers and a `--delay 1` or `--rps 2` to avoid being flagged for abuse.

---

## 🛠️ Performance Features

- **Concurrent Load**: Uses `asyncio` for efficient networking.
- **Archival Validity**: Validates PAdES B-LTA (DSS + Document Timestamps).
- **Graceful Cleanup**: Automatic handling of temporary test environment PKI.

---

## License
Distributed under the MIT License. See `LICENSE` for more information.
