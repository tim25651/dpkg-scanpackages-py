"""Pytest fixtures for dpkg-scanpackages-py tests."""

from __future__ import annotations

from pathlib import Path

import pytest

CURR_DIR = Path(__file__).parent
EXAMPLE_PATH = CURR_DIR / "ExamplePackages"
FOUR_MB_PATH = CURR_DIR / "4MBPackages"
ORIG_PATH = CURR_DIR / "OrigPackages"
NEWEST_PATH = CURR_DIR / "NewestPackages"
DEB_PATH = CURR_DIR / "pool/main/micromamba|1.5.8|apt.deb"

EXAMPLE_PKG = "micromamba"
EXAMPLE_VERSIONS = ["1.5.8-1", "1.5.9-1", "2.0.0-1", "2.0.2-1"]
EXAMPLE_ARCH = "all"


@pytest.fixture
def orig_packages() -> str:
    return ORIG_PATH.read_text("utf-8")


@pytest.fixture
def four_mb_packages() -> str:
    return FOUR_MB_PATH.read_text("utf-8")


@pytest.fixture
def only_newest_packages() -> str:
    return NEWEST_PATH.read_text("utf-8")


@pytest.fixture
def example_packages() -> list[dict[str, str]]:
    return [
        {"Package": EXAMPLE_PKG, "Version": version, "Architecture": EXAMPLE_ARCH}
        for version in EXAMPLE_VERSIONS
    ]


@pytest.fixture
def example_formatted() -> list[str]:
    return [
        f"Package: {EXAMPLE_PKG}\nVersion: {version}\nArchitecture: {EXAMPLE_ARCH}\n"
        for version in ["1.5.8-1", "1.5.9-1", "2.0.0-1", "2.0.2-1"]
    ]


@pytest.fixture
def example_content(example_formatted: list[str]) -> str:
    return "\n".join(example_formatted)


@pytest.fixture
def example_headers() -> dict[str, str]:
    return {
        "Package": "micromamba",
        "Version": "1.5.8-1",
        "Architecture": "all",
        "Maintainer": "Tim <tihoph@unknown>",
        "Installed-Size": "13959",
        "Filename": "pool/main/micromamba|1.5.8|apt.deb",
        "Size": "4811112",
        "MD5sum": "4e0a3eef41b6e1acf2bfbf6baeffb796",
        "SHA1": "fc4eb1ac04a0aff07de78de990db7b8a114c3bc5",
        "SHA256": "b95a374e54709668fd229e56151a6e368cf9b240058237fdde9a72bdf9574370",
        "Section": "unknown",
        "Priority": "optional",
        "Homepage": "<insert the upstream URL, if relevant>",
        "Description": """<insert up to 60 chars description>
 <insert long description, indented with spaces>""",
        "4MBSHA256": "eb32bb6537d6d822ef3f34dfdb33c3037c5d00f64fadb6aefccf785bbe29b43b",
    }
