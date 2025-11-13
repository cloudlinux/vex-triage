"""VEX client for fetching and parsing TuxCare VEX data."""

import json
import logging
from typing import Dict, List, Optional, Any
import requests

from src.utils import VexFetchError, retry_with_backoff


logger = logging.getLogger("tuxcare-vex")


class VexClient:
    """Client for fetching and parsing VEX data from TuxCare."""
    
    def __init__(self, ecosystem: str, vex_url: str):
        """
        Initialize VEX client.
        
        Args:
            ecosystem: Ecosystem name (java, python, javascript, php)
            vex_url: URL to the VEX JSON file
        """
        self.ecosystem = ecosystem
        self.vex_url = vex_url
        self._parsed_data: Optional[Dict[str, Any]] = None
    
    @retry_with_backoff(
        max_retries=3,
        initial_delay=1.0,
        exceptions=(requests.RequestException,)
    )
    def fetch_vex(self) -> Dict[str, Any]:
        """
        Fetch VEX data from URL with retry logic.
        
        Returns:
            Raw VEX data as dictionary
        
        Raises:
            VexFetchError: If fetch fails after all retries
        """
        logger.info(f"Fetching VEX data for {self.ecosystem} from {self.vex_url}")
        
        try:
            response = requests.get(self.vex_url, timeout=120)
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"Successfully fetched VEX data for {self.ecosystem}")
            
            # Log VEX metadata for freshness tracking
            if "metadata" in data and "timestamp" in data["metadata"]:
                timestamp = data["metadata"]["timestamp"]
                logger.info(f"VEX data timestamp: {timestamp}")
            
            return data
            
        except requests.Timeout as e:
            raise VexFetchError(f"Timeout fetching VEX data: {e}")
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                raise VexFetchError(f"VEX file not found: {self.vex_url}")
            raise VexFetchError(f"HTTP error fetching VEX data: {e}")
        except requests.RequestException as e:
            raise VexFetchError(f"Failed to fetch VEX data: {e}")
        except json.JSONDecodeError as e:
            raise VexFetchError(f"Invalid JSON in VEX data: {e}")
    
    def parse_vex(self, vex_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse VEX data into efficient lookup structures.
        
        Args:
            vex_data: Raw VEX data from fetch_vex()
        
        Returns:
            Parsed data with CVE index
        """
        logger.debug(f"Parsing VEX data for {self.ecosystem}")
        
        cve_index = self.build_cve_index(vex_data)
        
        metadata = {
            "timestamp": vex_data.get("metadata", {}).get("timestamp", "unknown"),
            "url": self.vex_url,
            "ecosystem": self.ecosystem,
        }
        
        logger.info(
            f"Parsed VEX data for {self.ecosystem}: "
            f"{len(cve_index)} unique CVEs indexed"
        )
        
        return {
            "metadata": metadata,
            "cve_index": cve_index,
        }
    
    def build_cve_index(self, vex_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build index mapping CVE IDs to affected packages.
        
        Args:
            vex_data: Raw VEX data
        
        Returns:
            Dictionary mapping CVE ID -> list of package info dicts
        """
        cve_index: Dict[str, List[Dict[str, Any]]] = {}
        
        vulnerabilities = vex_data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("id", "")
            if not cve_id:
                continue
            
            # Get analysis state
            analysis = vuln.get("analysis", {})
            state = analysis.get("state", "")
            detail = analysis.get("detail", "")
            
            # Get affected packages
            affects = vuln.get("affects", [])
            
            for affect in affects:
                ref = affect.get("ref", "")
                if not ref:
                    continue
                
                # Parse purl
                package_info = self.extract_package_info(ref)
                if not package_info:
                    continue
                
                package_info["state"] = state
                package_info["detail"] = detail
                package_info["purl"] = ref
                
                # Add to index
                if cve_id not in cve_index:
                    cve_index[cve_id] = []
                
                cve_index[cve_id].append(package_info)
        
        return cve_index
    
    def extract_package_info(self, purl: str) -> Optional[Dict[str, str]]:
        """
        Extract package information from Package URL (purl).
        
        Args:
            purl: Package URL (e.g., "pkg:maven/com.google.guava/guava@30.1-jre.tuxcare")
        
        Returns:
            Dictionary with ecosystem, namespace, name, version or None if parsing fails
        
        Example:
            Input: "pkg:maven/com.google.guava/guava@30.1-jre.tuxcare"
            Output: {
                "ecosystem": "maven",
                "namespace": "com.google.guava",
                "name": "guava",
                "version": "30.1-jre.tuxcare",
                "full_name": "com.google.guava:guava"
            }
        """
        if not purl or not purl.startswith("pkg:"):
            return None
        
        try:
            # Remove "pkg:" prefix
            purl = purl[4:]
            
            # Split ecosystem from rest
            if "/" not in purl:
                return None
            
            ecosystem, rest = purl.split("/", 1)
            
            # Extract version if present
            version = ""
            if "@" in rest:
                rest, version = rest.rsplit("@", 1)
            
            # Handle namespace and name
            parts = rest.split("/")
            if len(parts) == 1:
                # No namespace
                namespace = ""
                name = parts[0]
                full_name = name
            elif len(parts) == 2:
                # Has namespace
                namespace = parts[0]
                name = parts[1]
                full_name = f"{namespace}:{name}"
            else:
                # Multiple parts, join namespace
                namespace = "/".join(parts[:-1])
                name = parts[-1]
                # For Maven-style, use colon separator
                if ecosystem == "maven":
                    full_name = f"{namespace.replace('/', '.')}:{name}"
                else:
                    full_name = f"{namespace}/{name}"
            
            return {
                "ecosystem": ecosystem,
                "namespace": namespace,
                "name": name,
                "version": version,
                "full_name": full_name,
            }
            
        except Exception as e:
            logger.warning(f"Failed to parse purl '{purl}': {e}")
            return None
    
    def fetch_and_parse(self) -> Dict[str, Any]:
        """
        Fetch and parse VEX data (convenience method).
        
        Returns:
            Parsed VEX data with CVE index
        """
        # Use cached data if available
        if self._parsed_data is not None:
            logger.debug(f"Using cached VEX data for {self.ecosystem}")
            return self._parsed_data
        
        # Fetch and parse
        raw_data = self.fetch_vex()
        parsed_data = self.parse_vex(raw_data)
        
        # Cache in memory for this run
        self._parsed_data = parsed_data
        
        return parsed_data
    
    def find_cve_packages(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Find all packages affected by a CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
        
        Returns:
            List of package info dictionaries
        """
        if self._parsed_data is None:
            raise RuntimeError("VEX data not loaded. Call fetch_and_parse() first.")
        
        cve_index = self._parsed_data.get("cve_index", {})
        return cve_index.get(cve_id, [])
    
    def is_cve_resolved(self, cve_id: str, package_name: str) -> bool:
        """
        Check if a CVE is resolved for a specific package.
        
        Args:
            cve_id: CVE identifier
            package_name: Package name (e.g., "com.google.guava:guava")
        
        Returns:
            True if CVE is marked as resolved for the package
        """
        packages = self.find_cve_packages(cve_id)
        
        for pkg in packages:
            if pkg.get("full_name") == package_name and pkg.get("state") == "resolved":
                return True
        
        return False

