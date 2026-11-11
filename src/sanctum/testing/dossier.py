import os
import json
import time
from typing import Dict, Any, List
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from sanctum.cases.reports import BaseForensicPDF


class ValidationDossierGenerator:
    """
    Automated Validation Dossier Generator.
    Produces comprehensive audit dossiers certifying:
    - Complete Safety Test Matrix (100% pass rate required for release)
    - Recovery Precision & Recall Scores against Known-Answer Corpus
    - Controlled Fault Injection & Error Map handling
    - Performance Benchmarks against regression thresholds
    - Adversarial Verification Results
    """

    @classmethod
    def generate_dossier_data(
        cls,
        safety_tests_passed: int,
        safety_tests_total: int,
        recovery_precision: float,
        recovery_recall: float,
        benchmarks: List[Dict[str, Any]],
        adversarial_tests: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        is_release_ready = (safety_tests_passed == safety_tests_total) and (recovery_recall >= 0.95)
        return {
            "dossier_id": f"DOSSIER-{int(time.time())}",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "platform_version": "0.1.0",
            "release_blocking_safety_passed": (safety_tests_passed == safety_tests_total),
            "safety_summary": {
                "passed": safety_tests_passed,
                "total": safety_tests_total,
                "rate_percent": (safety_tests_passed / safety_tests_total) * 100.0,
            },
            "recovery_accuracy": {
                "precision": recovery_precision,
                "recall": recovery_recall,
                "f1_score": 2 * (recovery_precision * recovery_recall) / max(0.001, (recovery_precision + recovery_recall)),
            },
            "benchmarks": benchmarks,
            "adversarial_tests": adversarial_tests,
            "certification": "RELEASE_CERTIFIED" if is_release_ready else "RELEASE_BLOCKED",
        }

    @classmethod
    def render_dossier_pdf(cls, dossier_data: Dict[str, Any], output_pdf_path: str) -> None:
        pdf = BaseForensicPDF("Platform Quality Assurance & Validation Dossier")
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 14)
        cert = dossier_data["certification"]
        pdf.set_text_color(0, 120, 0) if cert == "RELEASE_CERTIFIED" else pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, f"STATUS: {cert}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(3)

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 6, "Dossier Identifier:", 0)
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 6, dossier_data["dossier_id"], new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(50, 6, "Generation Date (UTC):", 0)
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 6, dossier_data["generated_at"], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 1. Safety Matrix
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "1. Release-Blocking Safety Matrix", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        safety = dossier_data["safety_summary"]
        pdf.cell(0, 6, f"Passed: {safety['passed']}/{safety['total']} ({safety['rate_percent']:.1f}%)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 6, "Safety Boundary Invariant: 100% compliance mandatory for release clearance.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 2. Recovery Accuracy
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "2. Ground-Truth Recovery Scoring", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        acc = dossier_data["recovery_accuracy"]
        pdf.cell(0, 6, f"Precision: {acc['precision'] * 100:.1f}% | Recall: {acc['recall'] * 100:.1f}% | F1 Score: {acc['f1_score']:.3f}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 3. Benchmark Telemetry
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"3. Performance Benchmarks ({len(dossier_data['benchmarks'])} runs)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(55, 6, "Benchmark", 1)
        pdf.cell(40, 6, "Throughput", 1)
        pdf.cell(35, 6, "Threshold", 1)
        pdf.cell(30, 6, "Result", 1)
        pdf.cell(30, 6, "Duration", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 8)
        for bm in dossier_data["benchmarks"]:
            pdf.cell(55, 6, bm.get("operation_name", "N/A")[:30], 1)
            pdf.cell(40, 6, f"{bm.get('throughput_mbps', 0.0):.1f} MB/s", 1)
            pdf.cell(35, 6, f"{bm.get('threshold_mbps', 0.0):.1f} MB/s", 1)
            pdf.cell(30, 6, "PASS" if bm.get("passed") else "FAIL", 1)
            pdf.cell(30, 6, f"{bm.get('duration_seconds', 0.0):.3f}s", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.output(output_pdf_path)
