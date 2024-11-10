"""Command-line interface for dpkg-scanpackages.

Usage:
    dpkg-scanpackages [-m] [-a <arch>] [-t <type>] [-o <output>] <binary_path>
"""
# pragma: no cover

from __future__ import annotations

import sys
from argparse import ArgumentParser, Namespace
from importlib.metadata import PackageNotFoundError, version

from dpkg_scanpackages.scan_packages import DpkgScanPackages

script_version = "0.4.1"


class ScanPackagesNamespace(Namespace):
    """Namespace for command-line arguments."""

    binary_path: str
    multiversion: bool
    arch: str | None
    type: str
    output: str | None


def parse_args() -> ScanPackagesNamespace:
    """Parse command-line arguments."""
    try:
        final_script_version = version("dpkg_scanpackages")
    except PackageNotFoundError:
        final_script_version = script_version

    parser = ArgumentParser()
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="Debian %(prog)s version " + final_script_version + ".",
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
        type=str,
        action="store",
        dest="output",
        help="Write to file instead of stdout",
    )
    parser.add_argument("binary_path", type=str, help="path to the binary directory")

    return parser.parse_args()  # type: ignore[return-value]


def print_error(err: ValueError) -> None:
    """Print an error message."""
    print(f"{sys.argv[0]}: {err}")  # noqa: T201
    print()  # noqa: T201
    print("Use --help for program usage information.")  # noqa: T201


def scan_packages() -> None:
    """Main entry point."""
    args = parse_args()
    try:
        DpkgScanPackages(
            binary_path=args.binary_path,
            multiversion=args.multiversion,
            arch=args.arch,
            package_type=args.type,
            output=args.output,
            previous=None,
        ).scan()
    except ValueError as err:
        print_error(err)
