#!/usr/bin/env python3
"""Randomized differential cases: pypa/packaging (PEP 440)."""
import json
import random
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion

random.seed(20261003)

PRE = ["a1", "b2", "rc1", "alpha", "beta.3", "pre1", "c2"]
POST = ["post1", "post2", "-1", "rev3"]
DEV = ["dev1", "dev0", "dev10"]
LOCAL = ["ubuntu.1", "abc", "1.2", "local-1"]

def rand_version():
    v = ""
    if random.random() < 0.1:
        v += str(random.randint(0, 3)) + "!"
    segs = [str(random.randint(0, 5)) for _ in range(random.randint(1, 4))]
    v += ".".join(segs)
    if random.random() < 0.4:
        v += random.choice([".", "-", "_", ""]) + random.choice(PRE)
    if random.random() < 0.2:
        v += random.choice([".", "-", "_"]) + random.choice(POST) if random.random() < 0.7 else random.choice(POST)
    if random.random() < 0.2:
        v += random.choice([".", "-", "_", ""]) + random.choice(DEV)
    if random.random() < 0.15:
        v += "+" + random.choice(LOCAL)
    if random.random() < 0.1:
        v = "v" + v
    return v

def rand_spec_version():
    # versions usable in specifiers (no local for most operators)
    v = ""
    if random.random() < 0.1:
        v += str(random.randint(0, 2)) + "!"
    segs = [str(random.randint(0, 5)) for _ in range(random.randint(1, 4))]
    v += ".".join(segs)
    if random.random() < 0.35:
        v += random.choice(["", ".", "-"]) + random.choice(PRE)
    if random.random() < 0.15:
        v += "." + random.choice(["post1", "post2"])
    if random.random() < 0.15:
        v += ".dev" + str(random.randint(0, 3))
    return v

def rand_spec():
    op = random.choice(["==", "!=", "<", "<=", ">", ">=", "~="])
    v = rand_spec_version()
    if op in ("==", "!=") and random.random() < 0.25:
        # wildcard: strip to release only
        base = v.split("+")[0]
        for sep in ("a", "b", "rc", "alpha", "beta", "c", "pre", ".post", ".dev", "-"):
            idx = base.find(sep)
            if idx > 0 and (sep in ("a","b","c","rc","alpha","beta","pre") and not base[:idx].replace(".","").replace("!","").isdigit()):
                continue
            if idx > 0:
                base = base[:idx]
                break
        v = base + ".*"
    if op == "~=":
        # needs >= 2 release segments
        release = v.split("+")[0]
        if "!" in release:
            epoch, rest = release.split("!")
            prefix = epoch + "!"
        else:
            prefix, rest = "", release
        first = rest.split(".")[0]
        if "." not in rest:
            v = prefix + rest + "." + str(random.randint(0, 5))
    return op + v

def rand_spec_set():
    n = random.randint(1, 3)
    return ",".join(rand_spec() for _ in range(n))

N = 3000
out = {"specs": [], "compares": []}
skipped = 0
for _ in range(N):
    spec = rand_spec_set()
    version = rand_version()
    try:
        expected = Version(version) in SpecifierSet(spec)
    except (InvalidSpecifier, InvalidVersion):
        skipped += 1
        continue
    out["specs"].append({"spec": spec, "version": version, "expected": expected})

for _ in range(1500):
    a, b = rand_version(), rand_version()
    try:
        cmp = (Version(a) > Version(b)) - (Version(a) < Version(b))
    except InvalidVersion:
        continue
    out["compares"].append({"a": a, "b": b, "expected": cmp})

with open("testdata/pypi_fuzz.json", "w") as f:
    json.dump(out, f)
print("pypi fuzz cases:", len(out["specs"]), "skipped:", skipped,
      "compares:", len(out["compares"]))
