import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "extension"

spec = importlib.util.spec_from_file_location("build_extension", ROOT / "scripts" / "build_extension.py")
assert spec is not None and spec.loader is not None
build_extension = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_extension)


class ExtensionReleaseTests(unittest.TestCase):
    def test_manifest_has_only_user_initiated_permissions(self):
        manifest = json.loads((EXTENSION / "manifest.json").read_text())
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest.get("permissions"), ["activeTab", "scripting"])
        self.assertNotIn("host_permissions", manifest)
        self.assertNotIn("optional_host_permissions", manifest)
        self.assertNotIn("content_scripts", manifest)
        self.assertNotIn("background", manifest)

    def test_extension_source_is_local_only(self):
        forbidden = (
            "fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
            "chrome.storage", "http://", "https://",
        )
        for path in sorted(EXTENSION.rglob("*")):
            if path.suffix not in {".js", ".html", ".json"}:
                continue
            source = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, source, f"{marker!r} found in {path.relative_to(ROOT)}")

    def test_content_script_guards_against_duplicate_listeners(self):
        source = (EXTENSION / "content.js").read_text(encoding="utf-8")
        self.assertIn("__blindspotExtractorInstalled", source)
        self.assertEqual(source.count("chrome.runtime.onMessage.addListener"), 1)
        self.assertNotIn("DOMContentLoaded", source)

    def test_extracted_content_and_surface_payloads_are_bounded(self):
        source = (EXTENSION / "content.js").read_text(encoding="utf-8")
        self.assertIn("const MAX_CONTENT_CHARS = 80000", source)
        self.assertIn("const MAX_ATTACK_SURFACES = 100", source)
        self.assertIn("selection.slice(0, MAX_CONTENT_CHARS)", source)
        self.assertIn("join('\\n').slice(0, MAX_CONTENT_CHARS)", source)
        self.assertIn("editor.textContent.slice(0, MAX_CONTENT_CHARS)", source)
        self.assertIn("surfaces.length < MAX_ATTACK_SURFACES", source)

    def test_popup_scans_only_the_active_tab_and_handles_restricted_pages(self):
        source = (EXTENSION / "popup.js").read_text(encoding="utf-8")
        self.assertIn("active: true, currentWindow: true", source)
        self.assertIn("target: { tabId: tab.id }", source)
        self.assertIn("['http:', 'https:', 'file:'].includes(protocol)", source)
        self.assertIn("Chrome protects this page from extensions", source)
        self.assertNotIn("allFrames", source)

    def test_runtime_allowlist_matches_extension_tree(self):
        actual = {
            path.relative_to(EXTENSION).as_posix()
            for path in EXTENSION.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, set(build_extension.RUNTIME_FILES))

    def test_zip_is_allowlisted_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first.zip"
            second = Path(temp_dir) / "second.zip"
            build_extension.build(first)
            build_extension.build(second)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            with ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), sorted(build_extension.RUNTIME_FILES))
                self.assertTrue(all(info.date_time == build_extension.FIXED_TIMESTAMP for info in archive.infolist()))
                self.assertTrue(all(not name.startswith("/") and ".." not in Path(name).parts for name in archive.namelist()))


if __name__ == "__main__":
    unittest.main()
