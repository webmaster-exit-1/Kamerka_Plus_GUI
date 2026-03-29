"""
Tests that verify the Nuclei template manifest is consistent with the files on disk.
"""

import yaml
from pathlib import Path

from django.test import TestCase


class NucleiManifestTests(TestCase):

    def test_manifest_paths_exist(self):
        manifest_path = Path('nuclei_templates/manifest.yaml')
        self.assertTrue(manifest_path.exists(), "manifest.yaml not found")
        manifest = yaml.safe_load(manifest_path.read_text())
        for device_type, templates in manifest.get('mappings', {}).items():
            for template_path in templates:
                full_path = Path('nuclei_templates') / template_path
                self.assertTrue(
                    full_path.exists(),
                    f"Template listed in manifest does not exist: {template_path}",
                )
