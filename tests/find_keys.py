# %%
"""Find the key order."""

# ruff: noqa: PTH123
from __future__ import annotations

from itertools import pairwise

from tqdm import tqdm

from dpkg_scanpackages.scan_packages import read_packages_file

pkg_files = ["OrigPackages", "Packages2", "Packages (1)", "Packages (2)"]
ls: list[dict[str, str]] = []

for pkg_file in pkg_files:
    with open(pkg_file) as f:
        ls.extend(read_packages_file(f))

keys = [
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
    "Original-Vcs-Browser",
    "Original-Vcs-Git",
    "Cnf-Extra-Commands",
    "Cnf-Ignore-Commands",
    "Cnf-Visible-Pkgname",
    "Tag",
    "Task",
    "Protected",
    "Gstreamer-Decoders",
    "Gstreamer-Elements",
    "Gstreamer-Encoders",
    "Gstreamer-Uri-Sinks",
    "Gstreamer-Uri-Sources",
    "Gstreamer-Version",
    "Important",
    "Efi-Vendor",
    "Build-Ids",
    "Modaliases",
    "Pmaliases",
    "Python-Version",
    "Python3-Version",
    "Python-Egg-Name",
    "Postgresql-Catversion",
    "Ruby-Versions",
    "Go-Import-Path",
    "Lua-Versions",
    "Ghc-Package",
    "X-Cargo-Built-Using",
    "Description-md5",
    "Build-Essential",
    "Support",
]
for elem in tqdm(ls):
    if not set(elem).issubset(keys):
        missing = set(elem) - set(keys)
        print(f"Missing keys: {missing}")
        print(list(elem))
        break

ignore = {"Section"}
skip = {("Pre-Depends", "Depends"), ("Version", "Architecture")}
for a, b in pairwise(keys):
    if a in ignore or b in ignore:
        continue
    if (a, b) in skip:
        continue
    elems_with_both = [elem for elem in ls if {a, b}.issubset(set(elem))]
    # assert that a always comes before b
    for elem in elems_with_both:
        elem_keys = list(elem)
        idx_a = elem_keys.index(a)
        idx_b = elem_keys.index(b)
        if idx_a >= idx_b:
            print(f"idx_a: {idx_a}, idx_b: {idx_b}")
            print(elem_keys)
            print(a, b)


too_much = [
    "Original-Vcs-Browser",
    "Original-Vcs-Git",
    "Cnf-Extra-Commands",
    "Cnf-Ignore-Commands",
    "Cnf-Visible-Pkgname",
    "Gstreamer-Decoders",
    "Gstreamer-Elements",
    "Gstreamer-Encoders",
    "Gstreamer-Uri-Sinks",
    "Gstreamer-Uri-Sources",
    "Gstreamer-Version",
    "Efi-Vendor",
    "Build-Ids",
    "Modaliases",
    "Pmaliases",
    "Python-Version",
    "Python3-Version",
    "Python-Egg-Name",
    "Postgresql-Catversion",
    "Ruby-Versions",
    "Go-Import-Path",
    "Lua-Versions",
    "Ghc-Package",
    "X-Cargo-Built-Using",
]
too_much_set = set(too_much)
orig_sorted = [x for x in keys if x not in too_much_set]
print(orig_sorted)
