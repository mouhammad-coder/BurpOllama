import unittest

from core.reports import render_report, write_report_bundle


class DeprecatedReportExportTests(unittest.TestCase):
    def test_report_rendering_is_deprecated(self):
        with self.assertRaisesRegex(RuntimeError, "This command is deprecated"):
            render_report({"id": "scan"}, "hackerone")

    def test_report_bundle_does_not_write_report_files(self):
        with self.assertRaisesRegex(RuntimeError, "This command is deprecated"):
            write_report_bundle({"id": "scan"}, "reports")


if __name__ == "__main__":
    unittest.main()
