"""Scan packages and create the Packages file for the apt repository."""

from __future__ import annotations

from dpkg_scanpackages.cli import scan_packages

if __name__ == "__main__":
    scan_packages()
