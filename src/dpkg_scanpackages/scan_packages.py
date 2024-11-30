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

# Author: Raymond Velasquez <at.supermamon@gmail.com>

# ruff: noqa: PTH112, PTH123, PTH202

from __future__ import annotations

import hashlib
import os
from email import message_from_string
from pathlib import Path
from typing import IO, TYPE_CHECKING

from pydpkg.dpkg import Dpkg
from tqdm import tqdm

from dpkg_scanpackages.utils import (
    DpkgInfoHeaders,
    HasHeaders,
    multi_open_read,
    write_headers,
)

if TYPE_CHECKING:
    from _typeshed import SupportsRead

script_version = "0.4.1"

FOUR_MB = 4 * 1024 * 1024


class DpkgInfo:
    """Information about a dpkg package."""

    def __init__(self, binary_path: str, short_sha256: str | None = None) -> None:
        """Initialize the class."""
        self.binary_path = binary_path
        self.headers: dict[str, str] = {}
        pkg = Dpkg(self.binary_path)

        # build the information for the apt repo
        self.pkg = pkg
        self.headers = pkg.headers
        self.headers["Filename"] = pkg.filename.replace("\\", "/")
        self.headers["Size"] = pkg.filesize
        self.headers["MD5sum"] = pkg.md5
        self.headers["SHA1"] = pkg.sha1
        self.headers["SHA256"] = pkg.sha256

        if short_sha256 is None:
            self.headers["4MBSHA256"] = calculate_4mb_sha256(
                self.binary_path, pkg.filesize, pkg.sha256
            )
        else:
            self.headers["4MBSHA256"] = short_sha256


def read_packages_file(fd: SupportsRead[str]) -> list[dict[str, str]]:
    """Read an existing Packages file."""
    content = fd.read()
    sections = content.split("\n\n")
    return [dict(message_from_string(section)) for section in sections if section]


def calculate_4mb_sha256(
    filename: str, filesize: int, sha256: str | None = None
) -> str:
    """Get the SHA256 hash of the first 4MB of the file."""
    if (filesize <= FOUR_MB) and sha256:
        return sha256
    with open(filename, "rb") as file:
        return hashlib.sha256(file.read(FOUR_MB)).hexdigest()


def add_4mb_sha256(input: IO[str] | str, output: IO[str] | str | None) -> None:  # noqa: A002
    """Helper function to add 4MBSHA256 to an existing Packages file.

    Doesn't check if the packages have changed, just adds the 4MBSHA256 field.
    Additionally, sorts the packages by package name.
    """
    with multi_open_read(input) as read_fd:
        packages_ls = read_packages_file(read_fd)
    packages = {elem["Filename"]: elem for elem in packages_ls}
    packages = dict(sorted(packages.items()))

    for headers in packages.values():
        if "4MBSHA256" not in headers:
            headers["4MBSHA256"] = calculate_4mb_sha256(
                headers["Filename"], int(headers["Size"]), headers["SHA256"]
            )

    encapsulated = [DpkgInfoHeaders(elem) for elem in packages.values()]
    write_headers(output, encapsulated)


class DpkgScanPackages:
    """Scan packages in a directory and generate a Packages file."""

    def __init__(
        self,
        binary_path: str,
        multiversion: bool = False,
        package_type: str = "deb",
        arch: str | None = None,
        output: IO[str] | str | None = None,
        previous: IO[str] | str | tuple[str, ...] | None = None,
    ) -> None:
        """Initialize the class."""
        self.binary_path = binary_path

        # throw an error if it's an invalid path
        if not os.path.isdir(self.binary_path):
            raise ValueError(f"binary path {self.binary_path} not found")

        # options
        self.multiversion = multiversion
        self.package_type = package_type
        self.arch = arch
        self.output = output
        self.package_list: list[DpkgInfo | DpkgInfoHeaders] = []

        if previous is None:
            self.previous = {}
        else:
            with multi_open_read(previous) as fd:
                previous_ls = read_packages_file(fd)
            self.previous = {
                elem["Filename"]: DpkgInfoHeaders(elem) for elem in previous_ls
            }
            self.previous = dict(sorted(self.previous.items()))

    @staticmethod
    def _is_equal(curr: HasHeaders, prev: HasHeaders) -> bool:
        """Check if the file is equal to the previous."""
        prev_4mb_sha256 = prev.headers.get("4MBSHA256")
        prev_size_str = prev.headers.get("Size")
        if prev_4mb_sha256 is None or prev_size_str is None:
            return False

        prev_size = int(prev_size_str)
        curr_size = int(curr.headers["Size"])
        curr_4mb_sha256 = curr.headers["4MBSHA256"]
        return (prev_4mb_sha256 == curr_4mb_sha256) and (prev_size == curr_size)

    def _get_packages(self) -> None:
        """Get the packages."""
        # get all files

        cwd = Path.cwd()
        files = sorted(
            str(f.absolute().relative_to(cwd))
            for f in Path(self.binary_path).rglob(f"*.{self.package_type}")
        )

        for fname in tqdm(files, desc="Scanning packages"):
            # extract the package information
            size = os.path.getsize(fname)
            short_sha256 = calculate_4mb_sha256(fname, size)
            curr = DpkgInfoHeaders({"Size": str(size), "4MBSHA256": short_sha256})
            prev = self.previous.get(fname)

            if prev is not None and self._is_equal(curr, prev):
                print("Reusing previous package info for", fname)  # noqa: T201
                self.package_list.append(prev)
                continue

            pkg_info = DpkgInfo(fname, short_sha256)

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
                    matched_index, matched_item = matched_items[0]

                    dpkg = Dpkg(pkg_info.headers["Filename"])
                    if dpkg.compare_version_with(matched_item.headers["Version"]) == 1:
                        self.package_list[matched_index] = pkg_info
                    else:  # pragma: no cover
                        print("Skipping older version of", fname)  # noqa: T201

    def scan(
        self, return_list: bool = False
    ) -> list[DpkgInfo | DpkgInfoHeaders] | None:
        """Scan the packages."""
        self._get_packages()
        if return_list:
            return self.package_list

        write_headers(self.output, self.package_list)

        return None
