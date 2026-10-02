#!/usr/bin/env python3
"""Generates PyPI ground truth using pypa/packaging (PEP 440)."""
import json
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion

# (specifier_set, version) pairs; expected = version in SpecifierSet(spec)
spec_cases = [
    # prerelease boundaries (the acceptance focus)
    ("<1.4.2", "1.4.2rc1"),
    ("<1.4.2", "1.4.1"),
    ("<1.4.2", "1.4.2"),
    (">=1.0,<1.4.2", "1.4.2rc1"),
    (">=1.0,<1.4.2", "1.4.1"),
    (">=1.0,<1.4.2", "0.9"),
    ("<2.0", "2.0.dev1"),
    (">=1.0,<2.0", "2.0.dev1"),
    (">=1.0,<2.0", "1.9rc1"),
    ("==1.4.*", "1.4"),
    ("==1.4.*", "1.4.0"),
    ("==1.4.*", "1.4.1"),
    ("==1.4.*", "1.4rc1"),
    ("==1.4.*", "1.4.0rc1"),
    ("==1.4.*", "1.4.0.1"),
    ("==1.4.*", "1.5"),
    ("==1.4.*", "1.4+local"),
    ("~=2.2", "2.2"),
    ("~=2.2", "2.9"),
    ("~=2.2", "3.0"),
    ("~=2.2", "2.2rc1"),
    ("~=2.2", "2.1.9"),
    ("~=2.2.0", "2.2.5"),
    ("~=2.2.0", "2.3.0"),
    ("~=1.4.5.0", "1.4.5.7"),
    ("~=1.4.5.0", "1.4.6"),
    ("==1.0", "1.0"),
    ("==1.0", "1.0.0"),
    ("==1.0", "1.0+local"),
    ("==1.0", "1.0rc1"),
    ("==1.0+foo", "1.0+foo"),
    ("==1.0+foo", "1.0+bar"),
    ("==1.0+foo", "1.0"),
    ("!=1.1", "1.1.0"),
    ("!=1.1", "1.1rc1"),
    ("!=1.1", "1.2"),
    ("!=1.1.*", "1.1.5"),
    ("!=1.1.*", "1.2"),
    (">=1!1.0", "1!1.0"),
    (">=1!1.0", "2.0"),
    ("==1!1.0.*", "1!1.0.5"),
    ("==1!1.0.*", "1.0.5"),
    (">=1.0.post1", "1.0"),
    (">=1.0.post1", "1.0.post2"),
    ("<=1.0", "1.0.dev1"),
    ("<=1.0", "1.0"),
    (">1.0", "1.0.post1"),
    (">1.0", "1.0.0.1"),
    ("===1.0", "1.0"),
    ("", "1.0"),
    ("", "1.0rc1"),
    (">=1.0, !=1.1.*, <2", "1.1.5"),
    (">=1.0, !=1.1.*, <2", "1.2"),
    (">=1.0, !=1.1.*, <2", "1.2rc1"),
    ("~=0.6", "0.6.9"),
    ("~=0.6", "0.7"),
    ("==2.2.*", "2.2.0.dev1"),
    ("<1.0", "0.9.9"),
    ("<1.0", "1.0a1"),
    ("<=1.0", "1.0rc1"),
    (">=1.0rc1", "1.0rc1"),
    (">=1.0rc1", "1.0"),
    # operator-level prerelease/postrelease/local exclusions
    ("<1.4.2", "1.4.2.dev1"),
    ("<1.4.2", "1.4.1rc1"),
    ("<2", "2rc1"),
    ("<2", "2.dev1"),
    ("<2", "1.9.9"),
    (">1.0", "1.0.post1"),
    (">1.0", "1.0+local"),
    (">1.0", "1.0.1"),
    (">1.0.post1", "1.0.post2"),
    (">1.0.post1", "1.0.post1"),
    ("<=1.0", "1.0+local"),
    (">=1.0", "1.0+local"),
    ("==1.0.*", "1.0.0.5"),
    ("==1.0.*", "1.0.1.5"),
    ("~=1!2.2", "1!2.5"),
    ("~=1!2.2", "2.5"),
    ("~=2.2rc1", "2.2rc2"),
    ("~=2.2rc1", "2.2"),
    ("~=2.2rc1", "2.3"),
]

# (a, b) pairs; expected = sign(Version(a) vs Version(b))
compare_cases = [
    ("1.10.0", "1.9.0"),
    ("1.0", "1.0.0"),
    ("v1.0", "1.0"),
    ("1.0 ", " 1.0"),
    ("1.0.dev1", "1.0a1"),
    ("1.0a1", "1.0a1.dev1"),
    ("1.0a1.dev1", "1.0a1"),
    ("1.0a1", "1.0a1.post1"),
    ("1.0a1.post1", "1.0a2"),
    ("1.0a1", "1.0b1"),
    ("1.0b1", "1.0rc1"),
    ("1.0rc1", "1.0"),
    ("1.0c1", "1.0rc1"),
    ("1.0alpha1", "1.0a1"),
    ("1.0_beta1", "1.0b1"),
    ("1.0-pre1", "1.0rc1"),
    ("1.0", "1.0.post1"),
    ("1.0-1", "1.0.post1"),
    ("1.0rev1", "1.0.post1"),
    ("1.0", "1.0+abc"),
    ("1.0+abc", "1.0.post1"),
    ("1.0+abc.1", "1.0+abc.2"),
    ("1.0+1", "1.0+a"),
    ("1.0", "1.0.dev1"),
    ("1.0.dev1", "1.0.dev2"),
    ("1!1.0", "2.0"),
    ("1.0", "1!0.1"),
    ("1!1.0", "1!1.0"),
    ("0.9", "1.0a1"),
    ("1.0+foo", "1.0+bar"),
    ("1.0+foo", "1.0+foo.1"),
    ("2.0rc1", "2.0"),
    ("1.5.2", "1.5.10"),
]

# version strings; expected = parseable by packaging.Version
valid_cases = [
    "1.0", "v1.0", "1!1.0", "1.0a1", "1.0.alpha1", "1.0_a1", "1.0-a1",
    "1.0b2", "1.0rc1", "1.0c1", "1.0pre1", "1.0preview1",
    "1.0.post1", "1.0-1", "1.0rev1", "1.0r1", "1.0.dev1", "1.0dev1",
    "1.0+local.1", "1.0+ubuntu-1", "1.0+a_b.c", "1!1.0a1.post2.dev3+x",
    "1.0.0.0.0.1", "0.9", "2019.10",
    # invalid
    "1.0..1", "abc", "1.0-", "1.0+", "1!1!1.0", "1.0.*", "", "1.0_",
    "1.0dev", "1.0+foo..bar",
]

# specifier strings; expected = parseable by SpecifierSet
spec_valid_cases = [
    ">=1.0,<1.4.2", "~=2.2", "==1.4.*", "!=1.1.*", "===1.0", "<2",
    ">=1.0, !=1.1.*, <2", "", "  ==1.0 ", ">= 1.0", "==1!1.0.*",
    "~=1.4.5.0", "==1.0+foo", ">=1.0,,<2",
    "~=2", ">=1.0+foo", "<1.0+foo", "~=1.0+foo",
    # invalid
    "=>1.0", "><1.0", "==", "~=", "<1.0.*", ">1.0.*", "~=1.0.*",
    "==1.0.*.rc1", "==1.0rc1.*", "==1.0..1", "1.0", ">=abc",
]

out = {
    "specs": [
        {"spec": s, "version": v, "expected": Version(v) in SpecifierSet(s)}
        for s, v in spec_cases
    ],
    "compares": [
        {"a": a, "b": b,
         "expected": (Version(a) > Version(b)) - (Version(a) < Version(b))}
        for a, b in compare_cases
    ],
    "valids": [],
    "specValids": [],
}
for v in valid_cases:
    try:
        Version(v)
        ok = True
    except InvalidVersion:
        ok = False
    out["valids"].append({"version": v, "valid": ok})
for s in spec_valid_cases:
    try:
        SpecifierSet(s)
        ok = True
    except InvalidSpecifier:
        ok = False
    out["specValids"].append({"spec": s, "valid": ok})

with open("testdata/pypi_groundtruth.json", "w") as f:
    json.dump(out, f, indent=2)
print("specs:", len(out["specs"]), "compares:", len(out["compares"]),
      "valids:", len(out["valids"]), "specValids:", len(out["specValids"]))
