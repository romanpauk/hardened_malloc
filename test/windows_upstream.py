import argparse
import ctypes
import os
import pathlib
import subprocess
import sys


SUCCESS_TESTS = {
    "aligned_sized_delete_large",
    "aligned_sized_delete_small",
    "aligned_sized_delete_small_min_align",
    "calloc_overflow",
    "calloc_zeroed",
    "free_sized_large",
    "free_sized_small",
    "impossibly_large_malloc",
    "large_array_growth",
    "malloc_noreuse",
    "malloc_object_size",
    "malloc_object_size_offset",
    "malloc_object_size_zero",
    "malloc_zero_different",
    "read_after_free_small",
    "string_overflow",
    "uninitialized_read_large",
    "uninitialized_read_small",
}

FAIL_FAST_TESTS = {
    "delete_type_size_mismatch":
        "fatal allocator error: sized deallocation mismatch (small)\n",
    "double_free_large": "fatal allocator error: invalid free\n",
    "double_free_large_delayed": "fatal allocator error: invalid free\n",
    "double_free_small": "fatal allocator error: double free (quarantine)\n",
    "double_free_small_delayed": "fatal allocator error: double free (quarantine)\n",
    "invalid_free_small_region": "fatal allocator error: double free\n",
    "invalid_free_small_region_far":
        "fatal allocator error: invalid free within a slab yet to be used\n",
    "invalid_aligned_sized_delete_large":
        "fatal allocator error: sized deallocation mismatch (large)\n",
    "invalid_aligned_sized_delete_small":
        "fatal allocator error: sized deallocation mismatch (small)\n",
    "invalid_malloc_object_size_small":
        "fatal allocator error: invalid malloc_object_size\n",
    "invalid_malloc_object_size_small_quarantine":
        "fatal allocator error: invalid malloc_object_size (quarantine)\n",
    "invalid_malloc_usable_size_small":
        "fatal allocator error: invalid malloc_usable_size\n",
    "invalid_malloc_usable_size_small_quarantine":
        "fatal allocator error: invalid malloc_usable_size (quarantine)\n",
    "overflow_small_1_byte": "fatal allocator error: canary corrupted\n",
    "overflow_small_8_byte": "fatal allocator error: canary corrupted\n",
    "unaligned_free_large": "fatal allocator error: invalid free\n",
    "unaligned_free_small": "fatal allocator error: invalid unaligned free\n",
    "unaligned_malloc_usable_size_small":
        "fatal allocator error: invalid unaligned malloc_usable_size\n",
    "uninitialized_free":
        "fatal allocator error: invalid uninitialized allocator usage\n",
    "uninitialized_malloc_usable_size":
        "fatal allocator error: invalid uninitialized allocator usage\n",
    "uninitialized_realloc":
        "fatal allocator error: invalid uninitialized allocator usage\n",
    "write_after_free_small": "fatal allocator error: detected write after free\n",
    "write_after_free_small_reuse":
        "fatal allocator error: detected write after free\n",
}

ACCESS_VIOLATION_TESTS = {
    "overflow_large_1_byte",
    "overflow_large_8_byte",
    "read_after_free_large",
    "read_zero_size",
    "write_after_free_large",
    "write_after_free_large_reuse",
    "write_zero_size",
}

EXPECTED_STDOUT = {
    "read_after_free_small": "0\n" * 16,
    "string_overflow": "overflow by 0 bytes\n",
}

ALL_TESTS = SUCCESS_TESTS | set(FAIL_FAST_TESTS) | ACCESS_VIOLATION_TESTS
FAIL_FAST_STATUSES = {0xC0000602, 0xC0000409}
MSYS_FAIL_FAST_STATUS = 0x7F
ACCESS_VIOLATION_STATUS = 0xC0000005
MSYS_ACCESS_VIOLATION_STATUS = (-11) & 0xFFFFFFFF


class TestFailure(Exception):
    pass


def normalize_status(status):
    return status & 0xFFFFFFFF


def normalize_newlines(data):
    return data.replace(b"\r\n", b"\n")


def is_fail_fast(status):
    # WSL interoperability exposes only the low byte of a Windows process status.
    # MSYS2 maps an unhandled RaiseFailFastException to its generic fatal status.
    return status == MSYS_FAIL_FAST_STATUS or status in FAIL_FAST_STATUSES or status in {
        value & 0xFF for value in FAIL_FAST_STATUSES
    }


def is_access_violation(status):
    # MSYS2 translates an access violation to its POSIX SIGSEGV status.
    return status in {
        ACCESS_VIOLATION_STATUS,
        ACCESS_VIOLATION_STATUS & 0xFF,
        MSYS_ACCESS_VIOLATION_STATUS,
    }


def run_test(directory, name):
    executable = (directory / f"upstream-{name}.exe").resolve()
    if not executable.is_file():
        raise TestFailure(f"{name}: missing executable {executable}")
    try:
        result = subprocess.run(
            [str(executable)], cwd=directory, capture_output=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TestFailure(f"{name}: failed to execute: {error}") from error

    status = normalize_status(result.returncode)
    stdout = normalize_newlines(result.stdout)
    stderr = normalize_newlines(result.stderr)
    if name in SUCCESS_TESTS:
        if status != 0:
            raise TestFailure(f"{name}: exit status 0x{status:08x}, expected success")
        expected_stdout = EXPECTED_STDOUT.get(name)
        if expected_stdout is not None and stdout != expected_stdout.encode():
            raise TestFailure(f"{name}: unexpected stdout {stdout!r}")
    elif name in FAIL_FAST_TESTS:
        if not is_fail_fast(status):
            raise TestFailure(f"{name}: exit status 0x{status:08x}, expected fail-fast")
        expected_stderr = FAIL_FAST_TESTS[name].encode()
        if stderr != expected_stderr:
            raise TestFailure(f"{name}: unexpected stderr {stderr!r}")
    elif name in ACCESS_VIOLATION_TESTS:
        if not is_access_violation(status):
            raise TestFailure(
                f"{name}: exit status 0x{status:08x}, expected access violation"
            )
    else:
        raise TestFailure(f"{name}: missing expectation")


def main():
    parser = argparse.ArgumentParser(
        description="Run unchanged upstream allocator tests against the Windows DLL"
    )
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("tests", nargs="+")
    arguments = parser.parse_args()

    selected = set(arguments.tests)
    unknown = selected - ALL_TESTS
    missing = ALL_TESTS - selected
    if unknown or missing:
        raise TestFailure(
            f"test manifest mismatch (unknown={sorted(unknown)}, missing={sorted(missing)})"
        )

    if os.name == "nt":
        # Child processes inherit this mode, preventing crash UI from blocking CI.
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)

    for name in sorted(selected):
        print(f"running {name}", flush=True)
        run_test(arguments.directory, name)
    print(f"passed {len(selected)} unchanged upstream tests on Windows")


if __name__ == "__main__":
    try:
        main()
    except TestFailure as error:
        print(f"upstream Windows test failure: {error}", file=sys.stderr)
        sys.exit(1)
