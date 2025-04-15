import os
import struct
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class BuildPattern:
    name: str
    pattern: bytes
    offset: int
    callback: Optional[Callable[[bytes, int], int]] = None


PATTERNS = [
    BuildPattern("2025+", bytes.fromhex("6A00536A0457")  , +0x001C),
    BuildPattern("2020+", bytes.fromhex("6A00FF75FC8BCF"), +0x001D),
    BuildPattern(
        "2018+", 
        bytes.fromhex("33C05E8BE55DC3E8"), 
        +0x001A, 
        lambda data, offset: resolve_call_instruction(data, offset) + 0x0001
    ),
]


def get_files_rec(base_dir, pattern="Gw", extension=".exe"):
    return [
        str(path)
        for path in Path(base_dir).rglob(f"{pattern}*{extension}")
        if path.is_file()
    ]


def resolve_call_instruction(data, call_pos):
    opcode = struct.unpack_from("<B", data, call_pos)[0]
    if opcode != 0xE8 and opcode != 0xE9:
        return call_pos
    
    rel_offset = struct.unpack_from("<i", data, call_pos + 1)[0]

    target_addr = call_pos + 5 + rel_offset
    return resolve_call_instruction(data, target_addr)


def find_build_number(file_path, patterns):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        for pattern in patterns:
            pos = data.find(pattern.pattern)
            if pos != -1:
                build_pos = pos + pattern.offset
                if pattern.callback is not None:
                    build_pos = pattern.callback(data, build_pos)

                if build_pos + 4 <= len(data):
                    build_bytes = data[build_pos:build_pos + 4]
                    build = struct.unpack("<I", build_bytes)[0]
                    return build, pattern.name

    except Exception as e:
        print(f"Error reading {file_path}: {e}")

    return 0x0, "None"


def read_build_numbers(file_paths, patterns):
    results = []
    for path in file_paths:
        build_number, pattern_name = find_build_number(path, patterns)
        results.append((path, build_number, pattern_name))
    return results


def main():
    gw_files = get_files_rec(os.getcwd())
    builds = read_build_numbers(gw_files, PATTERNS)

    print(f"{'Path':<60} | {'Build':<10} | Pattern")
    print("-" * 90)
    for path, build, name in builds:
        print(f"{path:<60} | {build:<10} | {name}")


if __name__ == "__main__":
    main()
