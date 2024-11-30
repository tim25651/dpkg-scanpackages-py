"""Utility functions for dpkg-scanpackages."""

# ruff: noqa: PTH109, PTH123
from __future__ import annotations

import fileinput
import sys
from contextlib import contextmanager
from typing import IO, TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

    from _typeshed import SupportsRead, SupportsWrite
HEADER_ORDER = [
    "Package",
    "Version",
    "Architecture",
    "Built-Using",
    "Multi-Arch",
    "Essential",
    "Source",
    "Origin",
    "Maintainer",
    "Original-Maintainer",
    "Bugs",
    "Installed-Size",
    "Provides",
    "Pre-Depends",
    "Depends",
    "Recommends",
    "Suggests",
    "Conflicts",
    "Breaks",
    "Replaces",
    "Enhances",
    "Filename",
    "Size",
    "MD5sum",
    "SHA1",
    "SHA256",
    "SHA512",
    "Section",
    "Priority",
    "Homepage",
    "Description",
    "Tag",
    "Task",
    "Protected",
    "Important",
    "Description-md5",
    "Build-Essential",
    "Support",
]


class HasHeaders(Protocol):
    """Base class for dpkg package information."""

    headers: dict[str, str]


class DpkgInfoHeaders:
    """Just the headers of a dpkg package."""

    def __init__(self, headers: dict[str, str]) -> None:
        """Initialize the class."""
        self.headers = headers


def format_headers(headers: dict[str, str]) -> str:
    """Format the headers."""
    pretty = ""
    # add as per key order
    for key in HEADER_ORDER:
        if key in headers:
            pretty = pretty + (f"{key}: {headers[key]}\n")

    # add the rest alphabetically
    for key in sorted(headers):
        if key not in HEADER_ORDER:
            pretty = pretty + (f"{key}: {headers[key]}\n")
    return pretty


def write_headers(output: IO[str] | str | None, packages: Sequence[HasHeaders]) -> None:
    """Write the headers."""
    if not packages:
        raise ValueError("No packages to write")

    with multi_open_write(output) as file:
        file.write(format_headers(packages[0].headers))
        for p in packages[1:]:
            file.write("\n")
            file.write(format_headers(p.headers))


class FileInputRead(fileinput.FileInput[str]):
    """Implements a read(-1) function for FileInput."""

    def read(self, n: int = -1) -> str:
        """Read up to n characters from the file."""
        if n != -1:
            raise NotImplementedError("can only read fully")
        return "".join(self)


@contextmanager
def multi_open_read(
    input: IO[str] | str | tuple[str, ...] | None = None,  # noqa: A002
) -> Generator[SupportsRead[str]]:
    """Open the provided file, file handle or stdin for reading."""
    if input is None:
        yield sys.stdin
        return

    if isinstance(input, str | tuple):
        with FileInputRead(files=input) as file:
            yield file
        return
    yield input


@contextmanager
def multi_open_write(
    output: IO[str] | str | None = None,
) -> Generator[SupportsWrite[str]]:
    """Open the provided file, file handle or stdout for writing."""
    if output is None:
        yield sys.stdout
    elif isinstance(output, str):
        with open(output, "w") as file:
            yield file
    else:
        yield output
