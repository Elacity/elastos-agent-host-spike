# Measure branch only: switch off one permission in tests/confine.rs, in place.
import re, sys
kind, name = sys.argv[1], sys.argv[2]
p = "capsules/wallet-provider/tests/confine.rs"
s = open(p).read()
if kind == "syscall":
    pat = re.compile(r'\("%s", Some\((\d+)\), (None|Some\(\d+\))\)' % re.escape(name))
    assert len(pat.findall(s)) == 1, name
    s = pat.sub(lambda m: '("%s", None, %s)' % (name, m.group(2)), s)
else:
    i = s.index('#[cfg(target_arch = "x86_64")]\nconst LANDLOCK_LOADER_PATHS')
    j = s.index('];', i)
    block = s[i:j]
    k = block.index('        "%s",' % name)
    a = block.rindex('    (\n', 0, k)
    b = block.index('    ),\n', k) + len('    ),\n')
    s = s[:i] + block[:a] + block[b:] + s[j:]
open(p, "w").write(s)
print("switched off", kind, name)
