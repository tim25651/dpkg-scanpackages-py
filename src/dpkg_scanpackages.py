#!/usr/bin/env python3
"""Scan packages in a directory and generate a Packages file."""
# Copyright 2018 Raymond Velasquez

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script: dpkg-scanpackages.py # noqa: ERA001
# Author: Raymond Velasquez <at.supermamon@gmail.com>
from __future__ import annotations

import argparse
import sys
from contextlib import contextmanager
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from pydpkg import Dpkg
from tqdm import tqdm
from typing_extensions import override

if TYPE_CHECKING:
    from collections.abc import Generator

    from _typeshed import SupportsWrite

StrPath: TypeAlias = str | PathLike


script_name = "dpkg-scanpackages.py"
script_version = "0.4.1"


@contextmanager
def smart_open(output: Path | None = None) -> Generator[SupportsWrite[bytes]]:
    """Open the output file or stdout."""
    if output is None:
        yield sys.stdout.buffer
    else:
        with output.open("wb") as file:
            yield file


class DpkgInfo:
    """Information about a dpkg package."""

    def __init__(self, binary_path: StrPath) -> None:
        """Initialize the class."""
        self.binary_path = binary_path
        self.headers: dict[str, str] = {}
        pkg = Dpkg(self.binary_path)

        # build the information for the apt repo
        self.headers = pkg.headers
        self.headers["Filename"] = pkg.filename.replace("\\", "/")
        self.headers["Size"] = pkg.filesize
        self.headers["MD5sum"] = pkg.md5
        self.headers["SHA1"] = pkg.sha1
        self.headers["SHA256"] = pkg.sha256

    @override
    def __str__(self) -> str:
        pretty = ""
        key_order = [
            "Package",
            "Version",
            "Architecture",
            "Maintainer",
            "Depends",
            "Conflicts",
            "Breaks",
            "Replaces",
            "Filename",
            "Size",
            "MD5sum",
            "SHA1",
            "SHA256",
            "Section",
            "Description",
        ]
        # add as per key order
        for key in key_order:
            if key in self.headers:
                pretty = pretty + (f"{key}: {self.headers[key]}\n")

        # add the rest alphabetically
        for key in sorted(self.headers.keys()):
            if key not in key_order:
                pretty = pretty + (f"{key}: {self.headers[key]}\n")
        return pretty


class DpkgScanpackages:
    """Scan packages in a directory and generate a Packages file."""

    def __init__(
        self,
        binary_path: StrPath,
        multiversion: bool | None = None,
        package_type: str | None = None,
        arch: str | None = None,
        output: StrPath | None = None,
    ) -> None:
        """Initialize the class."""
        self.binary_path = Path(binary_path)

        # throw an error if it's an invalid path
        if not self.binary_path.is_dir():
            raise ValueError(f"binary path {self.binary_path} not found")

        # options
        self.multiversion = multiversion if multiversion is not None else False
        self.package_type = package_type if package_type is not None else "deb"
        self.arch = arch
        self.output = Path(output) if output is not None else None

        self.package_list: list[DpkgInfo] = []

    def _get_packages(self) -> None:
        """Get the packages."""
        # get all files
        files = self.binary_path.rglob(f"*.{self.package_type}")
        files_ls = list(files)

        for fname in tqdm(files_ls, desc="Scanning packages"):
            # extract the package information
            pkg_info = DpkgInfo(fname)

            # if arch is defined and does not match package, move on to the next
            if (
                self.arch is not None
                and str(pkg_info.headers["Architecture"]) != self.arch
            ):
                continue

            # if --multiversion switch is passed, append to the list
            if self.multiversion:
                self.package_list.append(pkg_info)
            else:
                # finf if package is already in the list
                matched_items = [
                    (index, pkg)
                    for (index, pkg) in enumerate(self.package_list)
                    if self.package_list
                    and pkg.headers["Package"] == pkg_info.headers["Package"]
                ]
                if len(matched_items) == 0:
                    # add if not
                    self.package_list.append(pkg_info)
                else:
                    # compare versions and add if newer
                    matched_index = matched_items[0][0]
                    matched_item = matched_items[0][1]

                    dpkg = Dpkg(pkg_info.headers["Filename"])
                    if dpkg.compare_version_with(matched_item.headers["Version"]) == 1:
                        self.package_list[matched_index] = pkg_info

    def scan(self, return_list: bool = False) -> list[DpkgInfo] | None:
        """Scan the packages."""
        self._get_packages()
        if return_list:
            return self.package_list

        with smart_open(self.output) as file:
            for p in self.package_list:
                p_b = str(p).encode("utf-8")
                file.write(p_b + b"\n")

        return None


def print_error(err: ValueError) -> None:
    """Print an error message."""
    import termcolor

    error_msg = termcolor.colored("error", "red", attrs=["bold"])
    print(f"{script_name}: {error_msg}: {err}")  # noqa: T201
    print()  # noqa: T201
    print("Use --help for program usage information.")  # noqa: T201


class ScanPackagesNamespace(argparse.Namespace):
    """Namespace for command-line arguments."""

    binary_path: Path
    multiversion: bool
    arch: str | None
    type: str
    output: Path | None


def parse_args() -> ScanPackagesNamespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="Debian %(prog)s version " + script_version + ".",
        help="show the version.",
    )
    parser.add_argument(
        "-m",
        "--multiversion",
        default=False,
        action="store_true",
        dest="multiversion",
        help="allow multiple versions of a single package.",
    )
    parser.add_argument(
        "-a",
        "--arch",
        type=str,
        default=None,
        action="store",
        dest="arch",
        help="architecture to scan for.",
    )
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        default="deb",
        action="store",
        dest="type",
        help="scan for <type> packages (default is 'deb').",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        action="store",
        dest="output",
        help="Write to file instead of stdout",
    )
    parser.add_argument("binary_path", type=Path, help="path to the binary directory")

    return parser.parse_args()  # type: ignore[return-value]


def main() -> None:
    """Main entry point."""
    args = parse_args()
    try:
        DpkgScanpackages(
            binary_path=args.binary_path,
            multiversion=args.multiversion,
            arch=args.arch,
            package_type=args.type,
            output=args.output,
        ).scan()
    except ValueError as err:
        print_error(err)


if __name__ == "__main__":
    main()
