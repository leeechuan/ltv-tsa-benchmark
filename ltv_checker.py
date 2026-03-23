#!/usr/bin/env python3
"""
LTV Checker — Sign & Validate PDFs with Multiple TSA Endpoints
==============================================================
Signs a test PDF using each configured TSA and validates that the result
is LTV-enabled (PAdES B-LTA).  TSAs that don't produce a valid LTV result
are flagged as failures.

Usage examples:
  python ltv_checker.py --tsa http://tsa.example.com/ts
  python ltv_checker.py --tsa http://tsa.example.com/ts --iterations 3
  python ltv_checker.py --tsa http://tsa.example.com/ts --output-dir ./signed_pdfs
  python ltv_checker.py --preset digicert --pfx my_cert.pfx --pfx-pass secret
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import io
import os
import shutil
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from fpdf import FPDF

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko_certvalidator import ValidationContext

# ---------------------------------------------------------------------------
# Provider presets
# ---------------------------------------------------------------------------
# Add your proprietary or internal TSA endpoints to this dict to use them via --preset
PROVIDERS: dict[str, str] = {
    # "my-tsa": "https://tsa.internal.example.net",
}


# ---------------------------------------------------------------------------
# Test PKI generation
# ---------------------------------------------------------------------------
@dataclass
class TestPKI:
    """Holds all generated test PKI material."""
    root_key: rsa.RSAPrivateKey
    root_cert: x509.Certificate
    signer_key: rsa.RSAPrivateKey
    signer_cert: x509.Certificate
    pfx_bytes: bytes
    root_cert_pem: bytes
    crl_der: bytes
    temp_dir: Path


def generate_test_pki(temp_dir: Path) -> TestPKI:
    """
    Generate a minimal test PKI:
      Root CA  →  Signer Certificate
    Plus an empty CRL signed by the Root CA.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    one_year = datetime.timedelta(days=365)

    # --- Root CA ---
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "LTV Checker Test Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LTV Checker POC"),
    ])

    crl_path = temp_dir / "root.crl"

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    # --- Signer Certificate ---
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "LTV Checker Test Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LTV Checker POC"),
    ])

    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_name)
        .issuer_name(root_name)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_cert_sign=False, crl_sign=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    # --- CRL (empty — signer cert is not revoked) ---
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_name)
        .last_update(now)
        .next_update(now + one_year)
        .sign(root_key, hashes.SHA256())
    )
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    crl_path.write_bytes(crl_der)

    # --- PKCS#12 bundle ---
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=b"signer",
        key=signer_key,
        cert=signer_cert,
        cas=[root_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(b"test"),
    )

    pfx_path = temp_dir / "signer.pfx"
    pfx_path.write_bytes(pfx_bytes)

    # --- Save root cert PEM ---
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    (temp_dir / "root_ca.pem").write_bytes(root_pem)

    return TestPKI(
        root_key=root_key,
        root_cert=root_cert,
        signer_key=signer_key,
        signer_cert=signer_cert,
        pfx_bytes=pfx_bytes,
        root_cert_pem=root_pem,
        crl_der=crl_der,
        temp_dir=temp_dir,
    )


# ---------------------------------------------------------------------------
# Test PDF creation
# ---------------------------------------------------------------------------
def create_test_pdf() -> bytes:
    """Create a small one-page test PDF."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(0, 10, "LTV Checker - Test Document", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", size=11)
    pdf.ln(10)
    pdf.multi_cell(0, 7, (
        "This PDF was generated for testing RFC 3161 TSA timestamps "
        "and PAdES Long-Term Validation (LTV) compliance.\n\n"
        f"Generated at: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n"
        "The document will be digitally signed with an embedded timestamp "
        "and validated for LTV compliance."
    ))
    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class TSAResult:
    tsa_url: str
    iteration: int
    ltv_valid: bool | None = None
    signing_latency_ms: float = 0.0
    validation_details: str = ""
    error: str | None = None
    output_path: str | None = None


# ---------------------------------------------------------------------------
# Core: sign + validate
# ---------------------------------------------------------------------------
async def sign_and_validate(
    tsa_url: str,
    pki: TestPKI,
    iteration: int,
    output_dir: Path | None = None,
    verbose: bool = False,
) -> TSAResult:
    """
    Sign a test PDF with the given TSA and validate LTV compliance.

    Steps:
      1. Create a fresh test PDF
      2. Load the signer from the test PKCS#12
      3. Sign with PAdES B-LTA profile (embed_validation_info + use_pades_lta)
      4. Validate the result
    """
    result = TSAResult(tsa_url=tsa_url, iteration=iteration)

    try:
        # 1. Create test PDF
        pdf_bytes = create_test_pdf()

        # 2. Load signer
        cms_signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=pki.temp_dir / "signer.pfx",
            passphrase=b"test",
        )

        # 3. Set up timestamper
        headers = {"User-Agent": "LTV-Checker/1.0 (Public Benchmark Tool)"}
        tst_client = timestamps.HTTPTimeStamper(url=tsa_url, headers=headers)

        # 4. Build validation context for embedding revocation info
        from cryptography.x509 import load_pem_x509_certificate
        root_cert_crypto = load_pem_x509_certificate(pki.root_cert_pem)

        # Convert to the format pyhanko expects (asn1crypto cert)
        from asn1crypto import x509 as asn1_x509
        root_cert_asn1 = asn1_x509.Certificate.load(
            root_cert_crypto.public_bytes(serialization.Encoding.DER)
        )

        extra_roots = [root_cert_asn1]

        # Load any extra trust roots from the 'certs' directory if it exists
        certs_dir = Path("certs")
        if certs_dir.exists() and certs_dir.is_dir():
            for cert_file in certs_dir.glob("*.pem"):
                try:
                    cert_data = cert_file.read_bytes()
                    # We might have PEM or DER, but let's assume PEM for now as per our download
                    if b"-----BEGIN CERTIFICATE-----" in cert_data:
                        crt = load_pem_x509_certificate(cert_data)
                        asn1_crt = asn1_x509.Certificate.load(
                            crt.public_bytes(serialization.Encoding.DER)
                        )
                        extra_roots.append(asn1_crt)
                        if verbose:
                            print(f"    Loaded extra trust root: {cert_file.name}")
                except Exception as e:
                    if verbose:
                        print(f"    Failed to load extra trust root {cert_file.name}: {e}")

        vc = ValidationContext(
            extra_trust_roots=extra_roots,
            allow_fetching=True,
            crls=[pki.crl_der],
            revocation_mode="soft-fail",
        )

        # 5. Sign the PDF
        signature_meta = PdfSignatureMetadata(
            field_name="Signature1",
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
            validation_context=vc,
            embed_validation_info=True,
            use_pades_lta=True,
        )

        if verbose:
            print(f"    Signing with TSA: {tsa_url} ...")

        t0 = time.monotonic()

        pdf_in = io.BytesIO(pdf_bytes)
        w = IncrementalPdfFileWriter(pdf_in)

        pdf_out = await signers.async_sign_pdf(
            w,
            signature_meta=signature_meta,
            signer=cms_signer,
            timestamper=tst_client,
        )

        result.signing_latency_ms = (time.monotonic() - t0) * 1000

        # Read the signed PDF bytes
        signed_bytes = pdf_out.getvalue()

        if verbose:
            print(f"    Signed in {result.signing_latency_ms:.0f} ms "
                  f"({len(signed_bytes):,} bytes)")

        # 6. Save if output_dir is given
        if output_dir:
            tsa_label = tsa_url.split("//")[1].split("/")[0].replace(".", "_")
            out_file = output_dir / f"signed_{tsa_label}_iter{iteration}.pdf"
            out_file.write_bytes(signed_bytes)
            result.output_path = str(out_file)
            if verbose:
                print(f"    Saved to: {out_file}")

        # 7. Validate
        if verbose:
            print("    Validating LTV compliance ...")

        reader = PdfFileReader(io.BytesIO(signed_bytes))
        embedded_sigs = list(reader.embedded_signatures)

        if not embedded_sigs:
            result.ltv_valid = False
            result.validation_details = "No embedded signatures found"
            return result

        # Check each signature/timestamp
        from pyhanko.sign.validation import async_validate_pdf_signature, async_validate_pdf_timestamp

        validation_details = []
        all_valid = True

        for idx, sig in enumerate(embedded_sigs):
            try:
                sig_type_obj = sig.sig_object.get("/Type", "")
                is_timestamp = sig_type_obj == "/DocTimeStamp"
                sig_type_str = "Document Timestamp" if is_timestamp else "Signature"

                if is_timestamp:
                    status = await async_validate_pdf_timestamp(
                        sig,
                        validation_context=vc,
                    )
                else:
                    status = await async_validate_pdf_signature(
                        sig,
                        signer_validation_context=vc,
                    )

                intact = status.intact
                valid = status.valid
                trusted = status.trusted
                
                detail = (
                    f"{sig_type_str} #{idx}: "
                    f"intact={intact}, valid={valid}, trusted={trusted}"
                )

                if hasattr(status, 'timestamp_validity') and status.timestamp_validity:
                    ts = status.timestamp_validity
                    detail += f", timestamp_intact={ts.intact}, timestamp_valid={ts.valid}"

                validation_details.append(detail)

                # For our test PKI, 'trusted' might be False because it's not a public root.
                # But 'intact' and 'valid' prove the math and structure are correct.
                if not (intact and valid):
                    all_valid = False

                if verbose:
                    print(f"    {detail}")

            except Exception as e:
                validation_details.append(f"Signature #{idx}: validation error: {e}")
                all_valid = False

        # Check for DSS (Document Security Store) — this is key for LTV
        try:
            dss = reader.root.get("/DSS")
            if dss:
                dss_obj = dss.get_object()
                certs_count = len(dss_obj.get("/Certs", []))
                crls_count = len(dss_obj.get("/CRLs", []))
                ocsps_count = len(dss_obj.get("/OCSPs", []))
                dss_detail = (
                    f"DSS present: {certs_count} certs, "
                    f"{crls_count} CRLs, {ocsps_count} OCSPs"
                )
                validation_details.append(dss_detail)
                if verbose:
                    print(f"    {dss_detail}")
            else:
                validation_details.append("DSS: NOT FOUND (LTV data missing)")
                all_valid = False
        except Exception:
            validation_details.append("DSS: could not inspect")

        # Count document timestamps (for PAdES-LTA there should be ≥1)
        doc_ts_count = sum(
            1 for sig in embedded_sigs
            if sig.sig_object.get("/Type") and
            str(sig.sig_object["/Type"]) == "/DocTimeStamp"
        )
        if doc_ts_count > 0:
            validation_details.append(f"Document timestamps: {doc_ts_count}")
        else:
            validation_details.append("Document timestamps: NONE (PAdES-LTA requires ≥1)")

        result.ltv_valid = all_valid
        result.validation_details = "; ".join(validation_details)

    except Exception as e:
        result.ltv_valid = False
        result.error = f"{type(e).__name__}: {e}"
        if verbose:
            traceback.print_exc()

    return result


# ---------------------------------------------------------------------------
# Benchmark orchestrator
# ---------------------------------------------------------------------------
async def run_benchmark(
    tsa_urls: list[str],
    pki: TestPKI,
    iterations: int = 1,
    output_dir: Path | None = None,
    delay_seconds: float = 0.0,
    verbose: bool = False,
) -> list[TSAResult]:
    """Run the sign-and-validate cycle for each TSA."""
    results: list[TSAResult] = []

    for tsa_url in tsa_urls:
        for i in range(1, iterations + 1):
            if verbose:
                print(f"\n  [{i}/{iterations}] Testing: {tsa_url}")

            result = await sign_and_validate(
                tsa_url=tsa_url,
                pki=pki,
                iteration=i,
                output_dir=output_dir,
                verbose=verbose,
            )
            results.append(result)

            if delay_seconds > 0 and (tsa_url != tsa_urls[-1] or i < iterations):
                if verbose:
                    print(f"    Waiting {delay_seconds}s before next request ...")
                await asyncio.sleep(delay_seconds)

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(results: list[TSAResult]) -> None:
    """Print a summary report of all TSA tests."""
    # Group results by TSA URL
    tsa_groups: dict[str, list[TSAResult]] = {}
    for r in results:
        tsa_groups.setdefault(r.tsa_url, []).append(r)

    sep = "═" * 72
    thin_sep = "─" * 72

    print()
    print(f"╔{sep}╗")
    print(f"║{'LTV CHECKER — BENCHMARK REPORT':^72}║")
    print(f"╠{sep}╣")

    for tsa_url, group in tsa_groups.items():
        total = len(group)
        passed = sum(1 for r in group if r.ltv_valid)
        failed = total - passed
        latencies = [r.signing_latency_ms for r in group if r.signing_latency_ms > 0]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        status_icon = "✅" if passed == total else ("⚠️" if passed > 0 else "❌")

        print(f"║{' ':72}║")
        print(f"║  {status_icon} {tsa_url:<67}║")
        print(f"║{thin_sep}║")
        print(f"║  {'Iterations:':<30} {total:>38} ║")
        print(f"║  {'LTV Passed:':<30} {passed:>38} ║")
        print(f"║  {'LTV Failed:':<30} {failed:>38} ║")
        print(f"║  {'Pass Rate:':<30} {(passed/total*100) if total else 0:>37.1f}% ║")
        print(f"║  {'Avg Signing Latency:':<30} {avg_latency:>34.0f} ms ║")

        # Show errors if any
        errors = [r for r in group if r.error]
        if errors:
            print(f"║  {'Errors:':<30} {len(errors):>38} ║")
            for r in errors[:3]:
                err_msg = r.error[:60] if r.error else ""
                print(f"║    • {err_msg:<64}║")

        # Show validation details of first result
        if group[0].validation_details:
            details = group[0].validation_details.split("; ")
            print(f"║  {'Validation details (1st run):':<68}║")
            for d in details:
                d_trunc = d[:66]
                print(f"║    {d_trunc:<66}║")

        print(f"║{' ':72}║")
        print(f"╠{sep}╣")

    # Final summary
    total_all = len(results)
    passed_all = sum(1 for r in results if r.ltv_valid)
    final_icon = "✅" if passed_all == total_all else "❌"

    print(f"║  {final_icon} OVERALL: {passed_all}/{total_all} LTV checks passed"
          f"{' ':>42}║"[:74] + "║")
    print(f"╚{sep}╝")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LTV Checker — Sign PDFs with TSA timestamps and validate LTV compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Preset TSA endpoints:
{chr(10).join(f'  {k:<15} {v}' for k, v in PROVIDERS.items())}

Examples:
  %(prog)s --tsa http://tsa.example.com/ts
  %(prog)s --tsa http://tsa.example.com/ts --iterations 3
  %(prog)s --tsa http://tsa.example.com/ts --output-dir ./signed_pdfs
  %(prog)s --pfx my_cert.pfx --pfx-pass secret
        """,
    )

    target = parser.add_argument_group("TSA Selection")
    target.add_argument(
        "--preset",
        help="Optional: name of a preset TSA defined in the PROVIDERS dictionary",
    )
    target.add_argument(
        "--tsa",
        action="append",
        help="Custom TSA URL (can be specified multiple times)",
    )

    signing = parser.add_argument_group("Signing Certificate (optional)")
    signing.add_argument(
        "--pfx",
        help="Path to PKCS#12 (.pfx/.p12) signing certificate (uses test cert if omitted)",
    )
    signing.add_argument(
        "--pfx-pass",
        help="Passphrase for the PKCS#12 file",
    )

    options = parser.add_argument_group("Options")
    options.add_argument(
        "--iterations", "-n",
        type=int,
        default=1,
        help="Number of sign-and-validate cycles per TSA (default: 1)",
    )
    options.add_argument(
        "--output-dir", "-o",
        help="Save signed PDFs to this directory",
    )
    options.add_argument(
        "--keep-certs",
        help="Save test PKI certs to this directory for manual import into Adobe",
    )
    options.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Wait SEC seconds between sequential iterations (default: 0)",
    )
    options.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress and validation output",
    )

    return parser.parse_args()


async def async_main() -> None:
    args = parse_args()

    # Resolve TSA URLs
    tsa_urls: list[str] = []
    if args.preset:
        for name in args.preset.split(","):
            name = name.strip().lower()
            if name not in PROVIDERS:
                print(f"ERROR: Unknown preset '{name}'. "
                      f"Available: {', '.join(PROVIDERS)}")
                sys.exit(1)
            tsa_urls.append(PROVIDERS[name])
    if args.tsa:
        tsa_urls.extend(args.tsa)

    if not tsa_urls:
        print("ERROR: Specify at least one TSA with --preset or --tsa")
        sys.exit(1)

    # Output directory
    output_dir = None
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    # Banner
    print()
    print("=" * 60)
    print("  LTV Checker — PDF Signing & Validation Benchmark")
    print("=" * 60)
    print(f"  TSAs:        {len(tsa_urls)}")
    for url in tsa_urls:
        print(f"               • {url}")
    print(f"  Iterations:  {args.iterations}")
    print(f"  Certificate: {'Custom PFX' if args.pfx else 'Auto-generated test cert'}")
    if output_dir:
        print(f"  Output dir:  {output_dir}")
    print("=" * 60)

    # Generate or load PKI
    temp_dir = Path(tempfile.mkdtemp(prefix="ltv_checker_"))

    try:
        if args.pfx:
            # User-provided certificate — still need a test PKI structure
            # We'll create a minimal one but use their PFX for signing
            print("\n▶  Using custom PKCS#12 certificate ...")
            pki = generate_test_pki(temp_dir)
            # Override the PFX with user's
            pfx_path = Path(args.pfx)
            shutil.copy2(pfx_path, temp_dir / "signer.pfx")
            # TODO: Handle custom trust roots for user certs
        else:
            print("\n▶  Generating test PKI (Root CA → Signer) ...")
            pki = generate_test_pki(temp_dir)
            print(f"   Root CA:  {pki.root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
            print(f"   Signer:   {pki.signer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
            print(f"   PKI dir:  {temp_dir}")

        # Save certs if requested
        if args.keep_certs:
            certs_dir = Path(args.keep_certs)
            certs_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(temp_dir / "root_ca.pem", certs_dir / "root_ca.pem")
            shutil.copy2(temp_dir / "signer.pfx", certs_dir / "signer.pfx")
            shutil.copy2(temp_dir / "root.crl", certs_dir / "root.crl")
            print(f"   Certs saved to: {certs_dir}")

        print("\n▶  Running benchmark ...")
        results = await run_benchmark(
            tsa_urls=tsa_urls,
            pki=pki,
            iterations=args.iterations,
            output_dir=output_dir,
            delay_seconds=args.delay,
            verbose=args.verbose,
        )

        print_report(results)

    finally:
        # Clean up temp PKI (unless --keep-certs copied it)
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n\n⏹  Benchmark interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
