"""Toolchain and compiler availability detector for C/C++ and Embedded Systems."""

import os
import shutil
import subprocess
from typing import Dict, Optional


class ToolchainDetector:
    """
    Detects the availability and version of host and cross-compilation toolchains.
    Faithfully reports tool availability without simulating execution.
    """

    @classmethod
    def get_tool_status(cls) -> Dict[str, Dict[str, any]]:
        tools = {
            "semgrep": {"cmd": "semgrep", "category": "static_analyzer"},
            "clang": {"cmd": "clang", "category": "compiler"},
            "clang_tidy": {"cmd": "clang-tidy", "category": "linter"},
            "cppcheck": {"cmd": "cppcheck", "category": "static_analyzer"},
            "gcc": {"cmd": "gcc", "category": "compiler"},
            "g++": {"cmd": "g++", "category": "compiler"},
            "arm_gcc": {"cmd": "arm-none-eabi-gcc", "category": "cross_compiler"},
            "custom_c_cpp_ast": {"cmd": None, "category": "ast_analyzer"}
        }

        status: Dict[str, Dict[str, any]] = {}

        for name, meta in tools.items():
            cmd = meta["cmd"]
            if cmd is None:
                status[name] = {
                    "available": True,
                    "category": meta["category"],
                    "version": "1.0.0-embedded",
                    "path": "internal"
                }
                continue

            executable = shutil.which(cmd)
            if executable:
                version_str = cls._get_version(executable)
                status[name] = {
                    "available": True,
                    "category": meta["category"],
                    "version": version_str,
                    "path": executable
                }
            else:
                status[name] = {
                    "available": False,
                    "category": meta["category"],
                    "version": None,
                    "path": None,
                    "reason": f"Tool '{cmd}' is not installed on system PATH."
                }

        return status

    @staticmethod
    def _get_version(executable_path: str) -> Optional[str]:
        try:
            res = subprocess.run(
                [executable_path, "--version"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False
            )
            first_line = (res.stdout or res.stderr).splitlines()[0]
            return first_line.strip()
        except Exception:
            return "installed"
