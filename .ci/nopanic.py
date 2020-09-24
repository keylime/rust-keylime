#!/usr/bin/env python3

import os

banned = ["unwrap(", "panic!("]

srcs = os.listdir("src")
print("Files to check: %s" % srcs)

failed = False
for f in srcs:
    print("Checking file %s" % f)
    contents = open("src/%s" % f, "r").read().split("#[cfg(test)]")[0]
    for b in banned:
        if b not in contents:
            continue

        failed = True
        print("File %s calls banned function: %s)" % (f, b))
    pass

exit(failed)
