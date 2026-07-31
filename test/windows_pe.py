import argparse
import pathlib
import re
import subprocess
import sys


PREFIXED_ALLOCATOR_EXPORTS = {
    "h_aligned_alloc",
    "h_calloc",
    "h_cfree",
    "h_free",
    "h_free_aligned_sized",
    "h_free_sized",
    "h_malloc",
    "h_malloc_object_size",
    "h_malloc_object_size_fast",
    "h_malloc_stats",
    "h_malloc_trim",
    "h_malloc_usable_size",
    "h_mallopt",
    "h_memalign",
    "h_posix_memalign",
    "h_pvalloc",
    "h_realloc",
    "h_reallocarray",
    "h_valloc",
}

LINUX_ALLOCATOR_EXPORTS = {
    name.removeprefix("h_") for name in PREFIXED_ALLOCATOR_EXPORTS
}

PRODUCTION_EXPORTS = PREFIXED_ALLOCATOR_EXPORTS | LINUX_ALLOCATOR_EXPORTS

TESTING_EXPORTS = {
    "h_malloc_test_fail_commit",
    "h_malloc_test_fail_metadata_commit",
    "h_malloc_test_fail_reserve",
}

MINGW_CXX_EXPORTS = {
    "_ZdaPv",
    "_ZdaPvRKSt9nothrow_t",
    "_ZdaPvSt11align_val_t",
    "_ZdaPvSt11align_val_tRKSt9nothrow_t",
    "_ZdaPvy",
    "_ZdaPvySt11align_val_t",
    "_ZdlPv",
    "_ZdlPvRKSt9nothrow_t",
    "_ZdlPvSt11align_val_t",
    "_ZdlPvSt11align_val_tRKSt9nothrow_t",
    "_ZdlPvy",
    "_ZdlPvySt11align_val_t",
    "_Znay",
    "_ZnayRKSt9nothrow_t",
    "_ZnaySt11align_val_t",
    "_ZnaySt11align_val_tRKSt9nothrow_t",
    "_Znwy",
    "_ZnwyRKSt9nothrow_t",
    "_ZnwySt11align_val_t",
    "_ZnwySt11align_val_tRKSt9nothrow_t",
}

MINGW_RUNTIME_IMPORTS = {"kernel32.dll", "msvcrt.dll"}
PRODUCTION_DLL_IMPORTS = MINGW_RUNTIME_IMPORTS | {
    "bcrypt.dll",
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
}
REQUIRED_DLL_CHARACTERISTICS = {"HIGH_ENTROPY_VA", "DYNAMIC_BASE", "NX_COMPAT"}


class ContractError(Exception):
    pass


def run_objdump(objdump, option, artifact):
    try:
        result = subprocess.run(
            [objdump, option, artifact], check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"failed to inspect {artifact}: {error}") from error
    return result.stdout


def inspect(objdump, artifact):
    output = run_objdump(objdump, "-p", artifact)
    is_pe32_plus = re.search(
        r"^Magic\s+020b\s+\(PE32\+\)$", output, re.MULTILINE
    )
    if "file format pei-x86-64" not in output or is_pe32_plus is None:
        raise ContractError(f"{artifact}: expected an x64 PE32+ image")

    imports = {name.lower() for name in re.findall(r"DLL Name:\s*(\S+)", output)}
    exports = set(
        re.findall(
            r"^\s*\[\s*\d+\]\s+\+base\[\s*\d+\]\s+[0-9a-fA-F]+\s+(\S+)\s*$",
            output,
            re.MULTILINE,
        )
    )
    characteristics = {
        name
        for name in REQUIRED_DLL_CHARACTERISTICS
        if re.search(rf"^\s*{re.escape(name)}\s*$", output, re.MULTILINE)
    }
    return imports, exports, characteristics, output


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


def check_library(objdump, artifact, expected_exports):
    imports, exports, characteristics, output = inspect(objdump, artifact)
    require_equal(artifact, "imports", imports, PRODUCTION_DLL_IMPORTS)
    require_equal(artifact, "exports", exports, expected_exports)
    require_equal(
        artifact,
        "DLL characteristics",
        characteristics,
        REQUIRED_DLL_CHARACTERISTICS,
    )
    if re.search(r"^\s*DLL\s*$", output, re.MULTILINE) is None:
        raise ContractError(f"{artifact}: image is not marked as a DLL")
    symbols = run_objdump(objdump, "-t", artifact)
    if re.search(r"emutls|pthread", symbols, re.IGNORECASE):
        raise ContractError(f"{artifact}: contains an emulated TLS or pthread symbol")


def check_import_library(objdump, artifact, expected_exports):
    symbols = run_objdump(objdump, "-t", artifact)
    names = set(
        re.findall(r"\)\s+0x[0-9a-fA-F]+\s+(\S+)\s*$", symbols, re.MULTILINE)
    )
    names |= {
        name.removeprefix("__imp_")
        for name in names
        if name.startswith("__imp_")
    }
    allocator_names = PRODUCTION_EXPORTS | TESTING_EXPORTS
    require_equal(
        artifact, "allocator import symbols", names & allocator_names, expected_exports
    )


def check_executable(objdump, artifact, allocator_dll=None):
    imports, exports, _characteristics, output = inspect(objdump, artifact)
    expected_imports = set(MINGW_RUNTIME_IMPORTS)
    if allocator_dll is not None:
        expected_imports.add(pathlib.Path(allocator_dll).name.lower())
    require_equal(artifact, "imports", imports, expected_imports)
    require_equal(artifact, "exports", exports, set())
    if re.search(r"^\s*DLL\s*$", output, re.MULTILINE) is not None:
        raise ContractError(f"{artifact}: test executable is marked as a DLL")


def main():
    parser = argparse.ArgumentParser(description="Validate the MinGW x64 PE binary contract")
    parser.add_argument("--objdump", required=True)
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
        arguments.objdump,
        arguments.library,
        PRODUCTION_EXPORTS | MINGW_CXX_EXPORTS,
    )
    check_import_library(
        arguments.objdump, arguments.import_library, PREFIXED_ALLOCATOR_EXPORTS
    )
    check_library(
        arguments.objdump,
        arguments.testing_library,
        PRODUCTION_EXPORTS | MINGW_CXX_EXPORTS | TESTING_EXPORTS,
    )
    check_import_library(
        arguments.objdump,
        arguments.testing_import_library,
        PREFIXED_ALLOCATOR_EXPORTS | TESTING_EXPORTS,
    )
    check_executable(arguments.objdump, arguments.vm_test)
    check_executable(arguments.objdump, arguments.smoke_test, arguments.library)
    check_executable(arguments.objdump, arguments.fault_test, arguments.library)
    check_executable(
        arguments.objdump, arguments.testing_test, arguments.testing_library
    )
    print("passed MinGW PE contract for 8 x64 artifacts")


if __name__ == "__main__":
    try:
        main()
    except ContractError as error:
        print(f"PE contract failure: {error}", file=sys.stderr)
        sys.exit(1)
