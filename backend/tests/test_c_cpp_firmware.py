"""Tests for C/C++ static security analysis, IoT firmware analyzer, and firmware synthesis."""

import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.scanners.c_cpp_analyzer import CCppSecurityAnalyzer
from app.services.scanners.toolchain import ToolchainDetector
from app.services.firmware_service import FirmwareService
from app.services.validation_service import ValidationService
from app.schemas.v1 import (
    FirmwareAnalysisRequest,
    FirmwareRefactorRequest,
    FirmwareSynthesisRequest
)

client = TestClient(app)
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "c_cpp_samples")


def test_toolchain_detector():
    """Verify toolchain detector faithfully reports installed and unavailable tools."""
    status = ToolchainDetector.get_tool_status()
    assert isinstance(status, dict)
    assert "semgrep" in status
    assert "clang" in status
    assert "gcc" in status
    assert "arm_gcc" in status
    assert "custom_c_cpp_ast" in status
    assert status["custom_c_cpp_ast"]["available"] is True


def test_buffer_overflow_detection():
    """Verify CWE-120/CWE-121 stack buffer overflow is detected with CVSS and line number."""
    with open(os.path.join(FIXTURES_DIR, "buffer_overflow.c"), "r", encoding="utf-8") as f:
        code = f.read()

    findings = CCppSecurityAnalyzer.scan_code(code, "buffer_overflow.c")
    assert len(findings) >= 1

    bof_finding = next((f for f in findings if "CWE-120" in f.cwe_id or "CWE-121" in f.cwe_id), None)
    assert bof_finding is not None
    assert bof_finding.severity in ("critical", "high")
    assert bof_finding.cvss_score >= 8.0
    assert "strcpy" in bof_finding.code_snippet
    assert bof_finding.line_start > 0


def test_use_after_free_detection():
    """Verify CWE-416 Use-After-Free is detected in C++ code."""
    with open(os.path.join(FIXTURES_DIR, "use_after_free.cpp"), "r", encoding="utf-8") as f:
        code = f.read()

    findings = CCppSecurityAnalyzer.scan_code(code, "use_after_free.cpp")
    assert len(findings) >= 1

    uaf_finding = next((f for f in findings if "CWE-416" in f.cwe_id), None)
    assert uaf_finding is not None
    assert uaf_finding.severity in ("critical", "high")
    assert uaf_finding.cvss_score >= 7.0
    assert "session" in uaf_finding.code_snippet


def test_iot_firmware_security_checks():
    """Verify IoT firmware specific security checks (MQTT, OTA, TLS bypass)."""
    # 1. Plaintext MQTT (CWE-319)
    with open(os.path.join(FIXTURES_DIR, "insecure_mqtt.c"), "r", encoding="utf-8") as f:
        mqtt_code = f.read()
    mqtt_findings = CCppSecurityAnalyzer.scan_code(mqtt_code, "insecure_mqtt.c", target_platform="esp32")
    assert any("CWE-319" in f.cwe_id for f in mqtt_findings)

    # 2. Unsigned OTA (CWE-494)
    with open(os.path.join(FIXTURES_DIR, "insecure_ota.c"), "r", encoding="utf-8") as f:
        ota_code = f.read()
    ota_findings = CCppSecurityAnalyzer.scan_code(ota_code, "insecure_ota.c", target_platform="esp32")
    assert any("CWE-494" in f.cwe_id for f in ota_findings)

    # 3. Missing TLS verification (CWE-295)
    with open(os.path.join(FIXTURES_DIR, "missing_tls_verification.cpp"), "r", encoding="utf-8") as f:
        tls_code = f.read()
    tls_findings = CCppSecurityAnalyzer.scan_code(tls_code, "missing_tls_verification.cpp", target_platform="arduino")
    assert any("CWE-295" in f.cwe_id for f in tls_findings)


def test_api_firmware_analysis():
    """Test POST /api/v1/firmware/analyze endpoint."""
    with open(os.path.join(FIXTURES_DIR, "hardcoded_creds.c"), "r", encoding="utf-8") as f:
        code = f.read()

    payload = {
        "source_code": code,
        "filename": "wifi_config.c",
        "target_platform": "esp32",
        "rtos": "FreeRTOS",
        "security_checks": ["memory", "communication", "ota_update", "device_auth", "embedded_system"]
    }

    res = client.post("/api/v1/firmware/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["target_platform"] == "esp32"
    assert data["summary"]["total"] >= 1
    assert any("CWE-798" in f["cwe_id"] for f in data["findings"])
    assert "device_auth" in data["risk_breakdown"]


def test_api_firmware_synthesis():
    """Test POST /api/v1/firmware/synthesize endpoint."""
    payload = {
        "target_platform": "esp32",
        "rtos": "FreeRTOS",
        "requirement": "Synthesize a secure MQTT telemetry client using TLS certificate verification.",
        "component_type": "communication"
    }

    res = client.post("/api/v1/firmware/synthesize", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "source_code" in data
    assert "header_code" in data
    assert "configuration_file" in data
    assert "unit_tests" in data
    assert "security_considerations" in data
    assert len(data["security_considerations"]) > 0
    assert "esp_mqtt" in data["source_code"].lower() or "mqtt" in data["source_code"].lower()


def test_api_firmware_refactor():
    """Test POST /api/v1/firmware/refactor endpoint."""
    insecure_code = """void copy_buffer(const char *src) {
    char dest[32];
    strcpy(dest, src);
}"""

    payload = {
        "insecure_code": insecure_code,
        "vulnerability_type": "CWE-120",
        "target_platform": "generic"
    }

    res = client.post("/api/v1/firmware/refactor", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "snprintf" in data["secure_code"]
    assert "diff" in data
    assert len(data["security_benefits"]) > 0


def test_api_firmware_toolchain():
    """Test GET /api/v1/firmware/toolchain endpoint."""
    res = client.get("/api/v1/firmware/toolchain")
    assert res.status_code == 200
    data = res.json()
    assert "semgrep" in data
    assert "custom_c_cpp_ast" in data


def test_c_cpp_patch_validation_pipeline():
    """Test that C/C++ patch validation executes 6 checks without simulating unrun tools."""
    orig_code = """#include <string.h>
void func(const char *in) {
    char buf[16];
    strcpy(buf, in);
}"""

    patched_code = """#include <stdio.h>
#include <string.h>
void func(const char *in) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%s", in);
}"""

    val_result = ValidationService.validate_patch(
        original_code=orig_code,
        patched_code=patched_code,
        target_cwe_id="CWE-120",
        file_name="safe_copy.c"
    )

    check_names = [c.name for c in val_result.checks]
    assert "syntax_check" in check_names
    assert "compilation" in check_names
    assert "static_security_rescan" in check_names
    assert "unit_tests" in check_names
    assert "regression_tests" in check_names
    assert "firmware_build" in check_names

    syntax_check = next(c for c in val_result.checks if c.name == "syntax_check")
    assert syntax_check.status == "passed"

    rescan_check = next(c for c in val_result.checks if c.name == "static_security_rescan")
    assert rescan_check.status == "passed"

    regression_check = next(c for c in val_result.checks if c.name == "regression_tests")
    assert regression_check.status == "passed"

    # Compiler and Firmware build are recorded faithfully (e.g. not_available if not on host)
    fw_check = next(c for c in val_result.checks if c.name == "firmware_build")
    assert fw_check.status == "not_available"
