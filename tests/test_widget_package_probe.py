import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import widget_package_probe as widget


CONFIG = b'<widget xmlns="http://www.w3.org/ns/widgets" id="test"><content src="index.html"/></widget>'


class WidgetProbeTests(unittest.TestCase):
    def make_zip(self, entries):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, body in entries:
                    archive.writestr(name, body)
        return stream.getvalue()

    def probe_bytes(self, body):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.wgt"
            path.write_bytes(body)
            return widget.probe(path)

    def package(self, html=b'<body onload="start()"><script src="js/a.js"></script></body>', extra=()):
        return self.make_zip([("config.xml", CONFIG), ("index.html", html), ("js/a.js", b"throw 'must not execute';"), *extra])

    def test_metadata_and_static_entry(self):
        result = self.probe_bytes(self.package())
        self.assertTrue(result["crc_checked"])
        self.assertEqual(result["manifest"]["entry"]["path"], "index.html")
        self.assertEqual(result["html"]["references"][0]["status"], "present")
        self.assertEqual(result["html"]["event_attributes"][0]["value"], "start()")

    def test_reference_boundaries(self):
        result = self.probe_bytes(self.package(b'<img src="../x"><img src="%2e%2e/x"><img src="missing.png"><script src="https://example.invalid/a.js"></script>'))
        self.assertEqual([x["status"] for x in result["html"]["references"]],
                         ["outside-package", "outside-package", "missing", "external"])

    def test_base_element_prevents_false_resolution(self):
        result = self.probe_bytes(self.package(b'<base href="other/"><script src="js/a.js"></script>'))
        self.assertEqual(result["html"]["references"][0]["status"], "unresolved-base-element")

    def test_crc_corruption_fails(self):
        packed = self.package()
        packed = packed.replace(b"throw 'must not execute';", b"throw 'MUST NOT EXECUTE';", 1)
        with self.assertRaisesRegex(widget.WidgetError, "CRC"):
            self.probe_bytes(packed)

    def test_zip_path_and_duplicate_fail(self):
        for extra in [[("../x", b"x")], [("index.html", b"duplicate")], [("a\\b", b"x")]]:
            with self.subTest(extra=extra), self.assertRaises(widget.WidgetError):
                self.probe_bytes(self.package(extra=extra))

    def test_budgets_fail_before_expansion(self):
        packed = self.package()
        for setting, limit in [("MAX_ARCHIVE", 16), ("MAX_MEMBERS", 1), ("MAX_MEMBER", 8), ("MAX_TOTAL", 8)]:
            with self.subTest(setting=setting), patch.object(widget, setting, limit):
                with self.assertRaisesRegex(widget.WidgetError, "budget"):
                    self.probe_bytes(packed)

    def test_manifest_errors_and_non_zip_fail(self):
        inputs = [b"not a ZIP", self.make_zip([("index.html", b"<body>")]),
                  self.make_zip([("config.xml", b'<!DOCTYPE widget [<!ENTITY x "y">]><widget/>')]),
                  self.make_zip([("config.xml", CONFIG.replace(b"index.html", b"https://example.invalid/x"))])]
        for body in inputs:
            with self.subTest(body=body[:30]), self.assertRaises(widget.WidgetError):
                self.probe_bytes(body)


if __name__ == "__main__":
    unittest.main()
