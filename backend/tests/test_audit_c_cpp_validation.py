"""Verification test suite for C/C++ vulnerability rules, IoT firmware checks, and 8-stage validation pipeline."""

import pytest
from app.services.scanners.c_cpp_analyzer import CCppSecurityAnalyzer
from app.services.validation_service import ValidationService
from app.storage.database import init_db, save_scan, save_finding, save_remediation


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_c_scanf_buffer_overflow_detection():
    code = (
        "#include <stdio.h>\n"
        "void read_input() {\n"
        "    char buffer[32];\n"
        "    scanf(\"%s\", buffer);\n"
        "}\n"
    )
    findings = CCppSecurityAnalyzer.scan_code(code, "input.c")
    rules = [f.rule_id for f in findings]
    assert "C-MEM-SCANF-OVERFLOW" in rules
    f = next(item for item in findings if item.rule_id == "C-MEM-SCANF-OVERFLOW")
    assert f.cwe_id == "CWE-120"
    assert f.severity in ("critical", "high")
    assert f.function_name == "read_input"
    assert f.line_start == 4


def test_cpp_reinterpret_cast_detection():
    code = (
        "class Base { public: virtual ~Base() {} };\n"
        "class Derived : public Base {};\n"
        "void convert(Base* b) {\n"
        "    Derived* d = reinterpret_cast<Derived*>(b);\n"
        "}\n"
    )
    findings = CCppSecurityAnalyzer.scan_code(code, "cast.cpp")
    rules = [f.rule_id for f in findings]
    assert "CPP-TYPE-UNSAFE-CAST" in rules
    f = next(item for item in findings if item.rule_id == "CPP-TYPE-UNSAFE-CAST")
    assert f.cwe_id == "CWE-704"
    assert f.function_name == "convert"


def test_cpp_array_delete_mismatch():
    code = (
        "void cleanup() {\n"
        "    int* arr = new int[50];\n"
        "    delete arr;\n"
        "}\n"
    )
    findings = CCppSecurityAnalyzer.scan_code(code, "leak.cpp")
    rules = [f.rule_id for f in findings]
    assert "CPP-MEM-ARRAY-DELETE-MISMATCH" in rules
    f = next(item for item in findings if item.rule_id == "CPP-MEM-ARRAY-DELETE-MISMATCH")
    assert f.cwe_id == "CWE-762"
    assert f.function_name == "cleanup"


def test_cpp_use_after_move():
    code = (
        "#include <utility>\n"
        "#include <string>\n"
        "void process() {\n"
        "    std::string msg = \"hello\";\n"
        "    auto other = std::move(msg);\n"
        "    printf(\"%s\", msg.c_str());\n"
        "}\n"
    )
    findings = CCppSecurityAnalyzer.scan_code(code, "move.cpp")
    rules = [f.rule_id for f in findings]
    assert "CPP-MEM-USE-AFTER-MOVE" in rules
    f = next(item for item in findings if item.rule_id == "CPP-MEM-USE-AFTER-MOVE")
    assert f.cwe_id == "CWE-672"


def test_iot_firmware_config_checks():
    sdkconfig_content = (
        "# CONFIG_SECURE_BOOT is not set\n"
        "# CONFIG_FLASH_ENCRYPTION_ENABLED is not set\n"
    )
    findings = CCppSecurityAnalyzer.scan_code(sdkconfig_content, "sdkconfig")
    rules = [f.rule_id for f in findings]
    assert "IOT-CFG-SECURE-BOOT-DISABLED" in rules
    assert "IOT-CFG-FLASH-ENCRYPTION-DISABLED" in rules

    freertos_cfg = (
        "#define configUSE_PREEMPTION 1\n"
        "#define configCHECK_FOR_STACK_OVERFLOW 0\n"
    )
    findings_rtos = CCppSecurityAnalyzer.scan_code(freertos_cfg, "FreeRTOSConfig.h")
    rules_rtos = [f.rule_id for f in findings_rtos]
    assert "IOT-CFG-STACK-OVERFLOW-DISABLED" in rules_rtos


def test_8_stage_validation_checks_structure():
    rem_id = "rem_val_stage_01"
    finding_id = "find_val_stage_01"
    orig_c_code = (
        "#include <stdio.h>\n"
        "void query() {\n"
        "    char b[10];\n"
        "    gets(b);\n"
        "}\n"
    )
    patched_c_code = (
        "#include <stdio.h>\n"
        "void query() {\n"
        "    char b[10];\n"
        "    fgets(b, sizeof(b), stdin);\n"
        "}\n"
    )

    save_scan({
        "id": "scan_c_01",
        "source_type": "source_code",
        "target_name": "query.c",
        "status": "completed",
        "source_code": orig_c_code
    })

    save_finding({
        "id": finding_id,
        "scan_id": "scan_c_01",
        "title": "Unsafe gets call",
        "severity": "critical",
        "cwe_id": "CWE-242",
        "rule_id": "C-MEM-GETS-OVERFLOW",
        "file_path": "query.c",
        "line_start": 4
    })

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_c_01",
        "finding_id": finding_id,
        "status": "completed",
        "original_code": orig_c_code,
        "patched_code": patched_c_code,
        "unified_diff": "--- a/query.c\n+++ b/query.c\n",
        "validation_status": "UNVALIDATED"
    })

    result = ValidationService.validate_remediation(remediation_id=rem_id, strict_mode=False)

    check_names = [c.name for c in result.checks]
    assert "source_parsing" in check_names
    assert "patch_generation" in check_names
    assert "patch_application" in check_names
    assert "compilation" in check_names
    assert "static_security_analysis" in check_names
    assert "dynamic_tests" in check_names
    assert "regression_tests" in check_names
    assert "firmware_build" in check_names

    # Check status values match specification
    for c in result.checks:
        assert c.status in ("passed", "failed", "error", "not_available", "blocked", "not_run")
