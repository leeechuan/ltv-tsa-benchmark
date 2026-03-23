import argparse
import asyncio
import io
import time
import math
import tempfile
import httpx
import base64
from pathlib import Path
from dataclasses import dataclass

# Cryptography and PyHanko
from fpdf import FPDF
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.sign.validation import async_validate_pdf_signature, async_validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509 as asn1_x509

KNOWN_TSA = {
    # Define your internal TSA presets here
    # "internal": "https://tsa.example.com",
}

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

@dataclass
class E2ETestResult:
    latency_ms: float
    success: bool
    error: str = None
    ltv_passed: bool = False

class TestPKI:
    def __init__(self, root_cert, signer_cert, crl_der, pfx_path, temp_dir):
        self.root_cert = root_cert
        self.signer_cert = signer_cert
        self.crl_der = crl_der
        self.pfx_path = pfx_path
        self.temp_dir = temp_dir

def generate_test_pki() -> TestPKI:
    """Synchronously generates the test certificates for the load test."""
    print("Generating isolated test PKI...")
    now = datetime.datetime.now(datetime.timezone.utc)
    one_year = datetime.timedelta(days=365)
    temp_dir = Path(tempfile.mkdtemp(prefix="ltv_e2e_"))

    root_key = rsa.generate_private_key(65537, 2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "E2E Test Root CA")])
    
    root_cert = (
        x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True,False,False,False,True,True,False,False,False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    signer_key = rsa.generate_private_key(65537, 2048)
    signer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "E2E Test Signer")])
    
    signer_cert = (
        x509.CertificateBuilder().subject_name(signer_name).issuer_name(root_name)
        .public_key(signer_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True,True,False,False,False,False,False,False,False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    crl = (x509.CertificateRevocationListBuilder()
        .issuer_name(root_name).last_update(now).next_update(now + one_year)
        .sign(root_key, hashes.SHA256()))
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    pfx = pkcs12.serialize_key_and_certificates(
        b"signer", signer_key, signer_cert, [root_cert],
        serialization.BestAvailableEncryption(b"test")
    )
    pfx_path = temp_dir / "signer.pfx"
    pfx_path.write_bytes(pfx)

    return TestPKI(root_cert, signer_cert, crl_der, pfx_path, temp_dir)

def generate_base_pdf() -> bytes:
    print("Generating base PDF document...")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(0, 10, "E2E LTV Load Test Document", new_x="LMARGIN", new_y="NEXT", align="C")
    return bytes(pdf.output())

async def e2e_worker(
    worker_id: int, 
    stop_event: asyncio.Event, 
    results: list,
    pki: TestPKI,
    pdf_bytes: bytes,
    meta: PdfSignatureMetadata,
    cms_signer: signers.SimpleSigner,
    tst_client: timestamps.HTTPTimeStamper,
    vc: ValidationContext,
    rate_limiter: RateLimiter | None = None
):
    """Worker that continually signs and validates PDFs until stop_event is set."""
    while not stop_event.is_set():
        if rate_limiter:
            await rate_limiter.wait()
            
        start_time = time.perf_counter()
        success = False
        ltv_passed = False
        err_msg = None

        try:
            # 1. Sign
            w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))
            
            # Using deepcopy to avoid PyHanko state issues across concurrent streams might be necessary, 
            # but IncrementalPdfFileWriter handles the stream. `cms_signer` and `tst_client` are generally thread-safe.
            # PyHanko's async_sign_pdf will block on the timestamp request inside.
            out_stream = await signers.async_sign_pdf(
                w, 
                signature_meta=meta, 
                signer=cms_signer, 
                timestamper=tst_client
            )
            
            signed_bytes = out_stream.getvalue()

            # 2. Validate
            reader = PdfFileReader(io.BytesIO(signed_bytes))
            embedded_sigs = list(reader.embedded_signatures)
            
            if not embedded_sigs:
                raise ValueError("No embedded signatures found after signing.")

            all_sigs_valid = True
            for sig in embedded_sigs:
                sig_type_obj = sig.sig_object.get("/Type", "")
                is_timestamp = sig_type_obj == "/DocTimeStamp"

                if is_timestamp:
                    status = await async_validate_pdf_timestamp(sig, validation_context=vc)
                else:
                    status = await async_validate_pdf_signature(sig, signer_validation_context=vc)

                # For LTV, we need math intact and signature valid. 
                # (Trusted may be False for document sig because of test PKI local trust roots)
                if not (status.intact and status.valid):
                    all_sigs_valid = False
            
            # 3. Check DSS
            has_dss = False
            dss = reader.root.get("/DSS")
            if dss:
                d = dss.get_object()
                certs = d.get("/Certs", [])
                crls = d.get("/CRLs", [])
                if len(certs) > 0 and len(crls) > 0:
                    has_dss = True
            
            if all_sigs_valid and has_dss:
                ltv_passed = True
                
            success = True

        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"
        
        latency = (time.perf_counter() - start_time) * 1000
        results.append(E2ETestResult(latency_ms=latency, success=success, error=err_msg, ltv_passed=ltv_passed))

async def main():
    parser = argparse.ArgumentParser(description="E2E Load Test: Signing + LTV Verification against RFC 3161 TSA")
    parser.add_argument("--preset", choices=KNOWN_TSA.keys(), help="Use a preset TSA")
    parser.add_argument("--tsa-url", type=str, help="Custom TSA URL")
    parser.add_argument("--duration", type=int, default=10, help="Test duration in seconds")
    parser.add_argument("--workers", type=int, default=5, help="Number of concurrent workers")
    parser.add_argument("--rps", type=float, help="Target requests per second across all workers (optional)")
    parser.add_argument("--hash-algo", type=str, default="sha256", choices=["sha256", "sha384", "sha512"])
    parser.add_argument("--username", type=str, help="Basic Auth Username")
    parser.add_argument("--password", type=str, help="Basic Auth Password")
    args = parser.parse_args()

    url = args.tsa_url
    if args.preset:
        url = KNOWN_TSA[args.preset]
    
    if not url:
        print("Error: Must provide either --preset or --tsa-url")
        return

    print("=" * 60)
    print(f"E2E Load Testing TSA: {url}")
    print(f"Duration: {args.duration}s | Workers: {args.workers} | Hash: {args.hash_algo}")
    print("=" * 60)

    # 1. Prepare global resources (PKI, Base PDF)
    pki = generate_test_pki()
    base_pdf = generate_base_pdf()

    root_cert_asn1 = asn1_x509.Certificate.load(pki.root_cert.public_bytes(serialization.Encoding.DER))
    vc = ValidationContext(
        extra_trust_roots=[root_cert_asn1],
        allow_fetching=True,
        crls=[pki.crl_der],
        revocation_mode="soft-fail",
    )

    cms_signer = signers.SimpleSigner.load_pkcs12(pfx_file=pki.pfx_path, passphrase=b"test")
    
    auth = None
    if args.username and args.password:
        auth = httpx.BasicAuth(args.username, args.password)
        
    auth_kwarg = {"auth": auth} if auth else {}

    # Setup the PyHanko HTTP Timestamp Client using httpx (for async compatibility out of the box mostly)
    # Note: HTTPTimeStamper itself does sync requests using requests, which might block the event loop!
    # BUT PyHanko's async_sign_pdf natively wraps it or we can provide an AIOHttp client.
    # PyHanko actually supports 'aiohttp' natively if installed, let's use the standard `timestamps.HTTPTimeStamper`
    # and PyHanko will handle it, or it will block the worker loop slightly. For perfectly safe async, 
    # we can use a custom timestamper, but let's test the native one first.
    headers = {"User-Agent": "E2E-LTV-Benchmark/1.0"}
    tst_client = timestamps.HTTPTimeStamper(url=url, headers=headers, **auth_kwarg)

    meta = PdfSignatureMetadata(
        field_name="Sig1",
        md_algorithm=args.hash_algo,
        subfilter=SigSeedSubFilter.PADES,
        validation_context=vc,
        embed_validation_info=True,
        use_pades_lta=True,
    )

    # 2. Start workers
    stop_event = asyncio.Event()
    results = []
    tasks = []
    rate_limiter = RateLimiter(args.rps) if args.rps and args.rps > 0 else None

    print(f"\nStarting {args.workers} concurrent workers...")
    for i in range(args.workers):
        t = asyncio.create_task(e2e_worker(
            i, stop_event, results, pki, base_pdf, meta, cms_signer, tst_client, vc, rate_limiter
        ))
        tasks.append(t)

    # 3. Wait for duration
    await asyncio.sleep(args.duration)
    
    print(f"Time's up! Signaling workers to stop...")
    stop_event.set()

    # Wait for workers to finish their final iteration
    await asyncio.gather(*tasks)

    # 4. Analyze Results
    total_reqs = len(results)
    if total_reqs == 0:
        print("\\nNo requests were completed.")
        return

    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]
    ltv_passes = [r for r in successes if r.ltv_passed]

    success_rate = (len(successes) / total_reqs) * 100
    ltv_rate = (len(ltv_passes) / total_reqs) * 100 if successes else 0
    throughput = total_reqs / args.duration

    latencies = [r.latency_ms for r in successes]
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    latencies.sort()
    p95_index = math.ceil(len(latencies) * 0.95) - 1
    p95_lat = latencies[p95_index] if latencies else 0

    print("\\n" + "=" * 60)
    print("E2E BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Total Sign+Verify Cycles: {total_reqs}")
    print(f"Successful Loops:         {len(successes)}")
    print(f"Failed Loops:             {len(failures)}")
    print(f"Success Rate (No Crash):  {success_rate:.2f}%")
    print(f"Valid LTV Pass Rate:      {len(ltv_passes)} / {total_reqs} ({ltv_rate:.2f}%)")
    print("-" * 60)
    print(f"Throughput (E2E):         {throughput:.2f} cycles/sec")
    print(f"Average Latency:          {avg_lat:.2f} ms")
    print(f"P95 Latency:              {p95_lat:.2f} ms")
    print("=" * 60)

    if failures:
        print("\\nTop Errors:")
        error_counts = {}
        for f in failures:
            error_counts[f.error] = error_counts.get(f.error, 0) + 1
        for err, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"- [{count}x] {err}")

    # Cleanup temp dir
    import shutil
    shutil.rmtree(pki.temp_dir, ignore_errors=True)

if __name__ == "__main__":
    import logging
    # Suppress pyhanko verbose logging running concurrently
    logging.getLogger("pyhanko").setLevel(logging.WARNING)
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.WARNING)
    asyncio.run(main())
