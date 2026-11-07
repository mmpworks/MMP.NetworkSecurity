"""Replaces the from-memory cipher prefix with a print, so the run can be compared with Microsoft's AesGcm."""
import pathlib

build = pathlib.Path(__file__).parent / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = '''assert TC3["cipher"].hex().startswith("42831ec2217774243b7261d5"), "GCM test case 3 cipher"
print("GCM test cases 1 and 3 match")'''
assert source.count(old) == 1
source = source.replace(old, '''print("GCM test case tags 1 and 3 match. TC3 cipher=" + TC3["cipher"].hex() + " tag=" + TC3["tag"])''')
old2 = '''print("GCM demo:", len(GCM_TEXT), "bytes,", len(sealed["blocks"]), "counters, tag", sealed["tag"])'''
assert source.count(old2) == 1
source = source.replace(old2, '''print("GCM demo:", len(GCM_TEXT), "bytes,", len(sealed["blocks"]), "counters, cipher=" + sealed["cipher"].hex() + " tag=" + sealed["tag"])''')
build.write_text(source, encoding="utf-8")
print("patched")
