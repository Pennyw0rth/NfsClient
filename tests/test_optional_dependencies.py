import subprocess
import sys
import unittest


class OptionalDependencyTests(unittest.TestCase):
    def test_base_import_does_not_require_impacket(self):
        subprocess.run((sys.executable, "-c", """
import builtins

def blocked_import(name, *args, normal_import=builtins.__import__, **kwargs):
    if name == "impacket" or name.startswith("impacket."):
        raise ModuleNotFoundError(name)
    return normal_import(name, *args, **kwargs)

builtins.__import__ = blocked_import
import pyNfsClient
assert pyNfsClient.NFSv40
assert pyNfsClient.NFSv41
assert pyNfsClient.NFSv42
"""), check=True)


if __name__ == "__main__":
    unittest.main()
