import argparse
import pathlib
import re
import subprocess
import sys

from windows_pe import (
    PREFIXED_ALLOCATOR_EXPORTS,
    PRODUCTION_EXPORTS,
    TESTING_EXPORTS,
)


REQUIRED_CHARACTERISTICS = {
    "High Entropy Virtual Addresses",
    "Dynamic base",
    "NX compatible",
}
MACHINE_NAMES = {"x64": "x64", "arm64": "ARM64"}
MSVC_CXX_EXPORTS = {
    "??2@YAPEAX_K@Z",
    "??_U@YAPEAX_K@Z",
    "??2@YAPEAX_KAEBUnothrow_t@std@@@Z",
    "??_U@YAPEAX_KAEBUnothrow_t@std@@@Z",
    "??3@YAXPEAX@Z",
    "??_V@YAXPEAX@Z",
    "??3@YAXPEAXAEBUnothrow_t@std@@@Z",
    "??_V@YAXPEAXAEBUnothrow_t@std@@@Z",
    "??3@YAXPEAX_K@Z",
    "??_V@YAXPEAX_K@Z",
    "??2@YAPEAX_KW4align_val_t@std@@@Z",
    "??_U@YAPEAX_KW4align_val_t@std@@@Z",
    "??2@YAPEAX_KW4align_val_t@std@@AEBUnothrow_t@1@@Z",
    "??_U@YAPEAX_KW4align_val_t@std@@AEBUnothrow_t@1@@Z",
    "??3@YAXPEAXW4align_val_t@std@@@Z",
    "??_V@YAXPEAXW4align_val_t@std@@@Z",
    "??3@YAXPEAXW4align_val_t@std@@AEBUnothrow_t@1@@Z",
    "??_V@YAXPEAXW4align_val_t@std@@AEBUnothrow_t@1@@Z",
    "??3@YAXPEAX_KW4align_val_t@std@@@Z",
    "??_V@YAXPEAX_KW4align_val_t@std@@@Z",
}


class ContractError(Exception):
    pass


def run_dumpbin(dumpbin, option, artifact):
    try:
        result = subprocess.run(
            [dumpbin, option, artifact], check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"failed to inspect {artifact}: {error}") from error
    return result.stdout


def inspect(dumpbin, artifact, arch):
    headers = run_dumpbin(dumpbin, "/headers", artifact)
    machine = MACHINE_NAMES[arch]
    if re.search(rf"\bmachine \({machine}\)", headers, re.IGNORECASE) is None:
        raise ContractError(f"{artifact}: expected an {arch} image")
    if "PE32+" not in headers:
        raise ContractError(f"{artifact}: expected a PE32+ image")

    missing_characteristics = {
        characteristic
        for characteristic in REQUIRED_CHARACTERISTICS
        if characteristic.lower() not in headers.lower()
    }
    if missing_characteristics:
        raise ContractError(
            f"{artifact}: missing image characteristics {sorted(missing_characteristics)}"
        )

    imports_output = run_dumpbin(dumpbin, "/imports", artifact)
    imports = {
        name.lower()
        for name in re.findall(
            r"^\s*([A-Za-z0-9_.-]+\.dll)\s*$", imports_output, re.MULTILINE
        )
    }

    exports_output = run_dumpbin(dumpbin, "/exports", artifact)
    exports = set(
        re.findall(
            r"^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s*$",
            exports_output,
            re.MULTILINE,
        )
    )
    return imports, exports


def require_equal(artifact, field, actual, expected):
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details = []
    if missing:
        details.append(f"missing {missing}")
    if unexpected:
        details.append(f"unexpected {unexpected}")
    raise ContractError(f"{artifact}: {field} mismatch ({'; '.join(details)})")


def is_windows_runtime_import(name):
    return (
        name in {"bcrypt.dll", "kernel32.dll", "ucrtbase.dll"}
        or re.fullmatch(r"msvcp\d+(?:_\d+)?\.dll", name) is not None
        or name.startswith("api-ms-win-")
        or name.startswith("ext-ms-win-")
        or re.fullmatch(r"vcruntime\d+(?:_\d+)?(?:_threads)?\.dll", name)
        is not None
    )


def check_imports(artifact, imports, permitted_allocator=None):
    unexpected = {
        name
        for name in imports
        if not is_windows_runtime_import(name) and name != permitted_allocator
    }
    if unexpected:
        raise ContractError(f"{artifact}: unexpected imports {sorted(unexpected)}")
    if any("pthread" in name or "libgcc" in name for name in imports):
        raise ContractError(f"{artifact}: contains an unexpected compiler runtime import")


def check_library(dumpbin, artifact, expected_exports, arch):
    imports, exports = inspect(dumpbin, artifact, arch)
    require_equal(artifact, "exports", exports, expected_exports)
    check_imports(artifact, imports)
    if "bcrypt.dll" not in imports:
        raise ContractError(f"{artifact}: missing bcrypt.dll entropy-provider import")


def check_import_library(dumpbin, artifact, expected_exports):
    output = run_dumpbin(dumpbin, "/linkermember:1", artifact)
    names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", output))
    names |= {
        name.removeprefix("__imp_")
        for name in names
        if name.startswith("__imp_")
    }
    allocator_names = PRODUCTION_EXPORTS | TESTING_EXPORTS
    require_equal(
        artifact, "allocator import symbols", names & allocator_names, expected_exports
    )


def check_executable(dumpbin, artifact, arch, allocator=None):
    imports, exports = inspect(dumpbin, artifact, arch)
    require_equal(artifact, "exports", exports, set())
    allocator_name = pathlib.Path(allocator).name.lower() if allocator else None
    check_imports(artifact, imports, allocator_name)
    if allocator_name and allocator_name not in imports:
        raise ContractError(f"{artifact}: missing allocator import {allocator_name}")


def main():
    parser = argparse.ArgumentParser(description="Validate the MSVC 64-bit PE binary contract")
    parser.add_argument("--arch", choices=sorted(MACHINE_NAMES), required=True)
    parser.add_argument("--dumpbin", required=True)
    parser.add_argument("--library", required=True)
    parser.add_argument("--import-library", required=True)
    parser.add_argument("--testing-library", required=True)
    parser.add_argument("--testing-import-library", required=True)
    parser.add_argument("--vm-test", required=True)
    parser.add_argument("--smoke-test", required=True)
    parser.add_argument("--fault-test", required=True)
    parser.add_argument("--testing-test", required=True)
    arguments = parser.parse_args()

    check_library(
        arguments.dumpbin,
        arguments.library,
        PRODUCTION_EXPORTS | MSVC_CXX_EXPORTS,
        arguments.arch,
    )
    check_import_library(
        arguments.dumpbin,
        arguments.import_library,
        PREFIXED_ALLOCATOR_EXPORTS,
    )
    check_library(
        arguments.dumpbin,
        arguments.testing_library,
        PRODUCTION_EXPORTS | MSVC_CXX_EXPORTS | TESTING_EXPORTS,
        arguments.arch,
    )
    check_import_library(
        arguments.dumpbin,
        arguments.testing_import_library,
        PREFIXED_ALLOCATOR_EXPORTS | TESTING_EXPORTS,
    )
    check_executable(arguments.dumpbin, arguments.vm_test, arguments.arch)
    check_executable(
        arguments.dumpbin, arguments.smoke_test, arguments.arch, arguments.library
    )
    check_executable(
        arguments.dumpbin, arguments.fault_test, arguments.arch, arguments.library
    )
    check_executable(
        arguments.dumpbin,
        arguments.testing_test,
        arguments.arch,
        arguments.testing_library,
    )
    print(f"passed MSVC PE contract for 8 {arguments.arch} artifacts")


if __name__ == "__main__":
    try:
        main()
    except ContractError as error:
        print(f"PE contract failure: {error}", file=sys.stderr)
        sys.exit(1)
