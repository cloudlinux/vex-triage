"""Unit tests for vex_client module."""

import unittest
import json
import os
from src.vex_client import VexClient


class TestVexClient(unittest.TestCase):
    """Test cases for VexClient class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = VexClient("java", "https://example.com/vex.json")
        
        # Load sample VEX data
        fixture_path = os.path.join(
            os.path.dirname(__file__),
            "fixtures",
            "sample_vex.json"
        )
        with open(fixture_path, "r") as f:
            self.sample_vex = json.load(f)
    
    def test_extract_package_info_maven(self):
        """Test extracting package info from Maven purl."""
        purl = "pkg:maven/com.google.guava/guava@30.1-jre.tuxcare"
        info = self.client.extract_package_info(purl)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["ecosystem"], "maven")
        self.assertEqual(info["namespace"], "com.google.guava")
        self.assertEqual(info["name"], "guava")
        self.assertEqual(info["version"], "30.1-jre.tuxcare")
        self.assertEqual(info["full_name"], "com.google.guava:guava")
    
    def test_extract_package_info_npm(self):
        """Test extracting package info from npm purl."""
        purl = "pkg:npm/@babel/core@7.0.0"
        info = self.client.extract_package_info(purl)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["ecosystem"], "npm")
        self.assertEqual(info["namespace"], "@babel")
        self.assertEqual(info["name"], "core")
        self.assertEqual(info["version"], "7.0.0")
    
    def test_extract_package_info_no_namespace(self):
        """Test extracting package info without namespace."""
        purl = "pkg:npm/lodash@4.17.21"
        info = self.client.extract_package_info(purl)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["ecosystem"], "npm")
        self.assertEqual(info["namespace"], "")
        self.assertEqual(info["name"], "lodash")
        self.assertEqual(info["version"], "4.17.21")
        self.assertEqual(info["full_name"], "lodash")
    
    def test_extract_package_info_invalid(self):
        """Test extracting package info from invalid purl."""
        # No pkg: prefix
        info = self.client.extract_package_info("maven/guava@1.0.0")
        self.assertIsNone(info)
        
        # Empty string
        info = self.client.extract_package_info("")
        self.assertIsNone(info)
        
        # No slash
        info = self.client.extract_package_info("pkg:maven")
        self.assertIsNone(info)
    
    def test_parse_vex(self):
        """Test parsing VEX data."""
        parsed = self.client.parse_vex(self.sample_vex)
        
        self.assertIn("metadata", parsed)
        self.assertIn("cve_index", parsed)
        
        # Check metadata
        metadata = parsed["metadata"]
        self.assertEqual(metadata["ecosystem"], "java")
        self.assertIn("timestamp", metadata)
        
        # Check CVE index
        cve_index = parsed["cve_index"]
        self.assertIn("CVE-2020-8908", cve_index)
        self.assertIn("CVE-2023-2976", cve_index)
    
    def test_build_cve_index(self):
        """Test building CVE index."""
        cve_index = self.client.build_cve_index(self.sample_vex)
        
        # Check CVE-2020-8908
        self.assertIn("CVE-2020-8908", cve_index)
        packages = cve_index["CVE-2020-8908"]
        self.assertEqual(len(packages), 1)
        
        pkg = packages[0]
        self.assertEqual(pkg["state"], "resolved")
        self.assertEqual(pkg["full_name"], "com.google.guava:guava")
        self.assertEqual(pkg["version"], "30.1-jre.tuxcare")
    
    def test_build_cve_index_multiple_states(self):
        """Test CVE index with different states."""
        cve_index = self.client.build_cve_index(self.sample_vex)
        
        # CVE-2024-9999 should have state "not_affected"
        self.assertIn("CVE-2024-9999", cve_index)
        packages = cve_index["CVE-2024-9999"]
        pkg = packages[0]
        self.assertEqual(pkg["state"], "not_affected")
    
    def test_find_cve_packages(self):
        """Test finding packages for a CVE."""
        # First parse the data
        parsed = self.client.parse_vex(self.sample_vex)
        self.client._parsed_data = parsed
        
        # Find packages for CVE-2020-8908
        packages = self.client.find_cve_packages("CVE-2020-8908")
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["full_name"], "com.google.guava:guava")
        
        # Find packages for non-existent CVE
        packages = self.client.find_cve_packages("CVE-9999-9999")
        self.assertEqual(len(packages), 0)
    
    def test_find_cve_packages_not_loaded(self):
        """Test finding CVE packages when data not loaded."""
        with self.assertRaises(RuntimeError):
            self.client.find_cve_packages("CVE-2020-8908")
    
    def test_is_cve_resolved(self):
        """Test checking if CVE is resolved."""
        # Parse and cache data
        parsed = self.client.parse_vex(self.sample_vex)
        self.client._parsed_data = parsed
        
        # CVE-2020-8908 is resolved for guava
        result = self.client.is_cve_resolved(
            "CVE-2020-8908",
            "com.google.guava:guava"
        )
        self.assertTrue(result)
        
        # CVE-2024-9999 is not resolved (state is "not_affected")
        result = self.client.is_cve_resolved(
            "CVE-2024-9999",
            "com.google.guava:guava"
        )
        self.assertFalse(result)
        
        # Non-existent CVE
        result = self.client.is_cve_resolved(
            "CVE-9999-9999",
            "com.google.guava:guava"
        )
        self.assertFalse(result)
        
        # Wrong package
        result = self.client.is_cve_resolved(
            "CVE-2020-8908",
            "wrong:package"
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()

