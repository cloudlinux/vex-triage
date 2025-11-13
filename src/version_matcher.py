"""Version matching logic for TuxCare VEX Auto-Triage."""

import logging
import re
from typing import Optional, List, Tuple
from packaging import version as pkg_version


logger = logging.getLogger("tuxcare-vex")


class VersionMatcher:
    """Handles version parsing and range matching."""
    
    @staticmethod
    def normalize_version(version_str: str) -> str:
        """
        Normalize version string for comparison.
        
        Handles TuxCare suffixes and common version formats.
        
        Args:
            version_str: Original version string
        
        Returns:
            Normalized version string
        
        Example:
            "30.1-jre.tuxcare" -> "30.1-jre"
            "2.7.18.tuxcare.3" -> "2.7.18"
        """
        if not version_str:
            return ""
        
        # Strip .tuxcare suffix and any following version counter
        # Pattern: .tuxcare or .tuxcare.N
        normalized = re.sub(r'\.tuxcare(\.\d+)?$', '', version_str)
        
        return normalized
    
    @staticmethod
    def parse_version(version_str: str) -> Optional[pkg_version.Version]:
        """
        Parse version string to packaging.Version object.
        
        Args:
            version_str: Version string to parse
        
        Returns:
            Version object or None if parsing fails
        """
        if not version_str:
            return None
        
        try:
            # Try direct parsing first
            return pkg_version.parse(version_str)
        except Exception:
            # If it fails, try normalizing first
            try:
                normalized = VersionMatcher.normalize_version(version_str)
                return pkg_version.parse(normalized)
            except Exception as e:
                logger.debug(f"Failed to parse version '{version_str}': {e}")
                return None
    
    @staticmethod
    def parse_range_spec(range_spec: str) -> List[Tuple[str, str]]:
        """
        Parse GitHub's version range specification.
        
        Args:
            range_spec: Range specification (e.g., ">= 1.0.0, < 2.0.0")
        
        Returns:
            List of (operator, version) tuples
        
        Examples:
            ">= 1.0.0, < 2.0.0" -> [(">=", "1.0.0"), ("<", "2.0.0")]
            "= 1.5.0" -> [("=", "1.5.0")]
        """
        if not range_spec:
            return []
        
        ranges = []
        
        # Split by comma
        parts = [p.strip() for p in range_spec.split(",")]
        
        for part in parts:
            if not part:
                continue
            
            # Match operator and version
            # Operators: >=, <=, >, <, =, !=
            match = re.match(r'^([><=!]+)\s*(.+)$', part)
            if match:
                operator = match.group(1)
                ver = match.group(2).strip()
                ranges.append((operator, ver))
            else:
                # Try without operator (assume exact match)
                logger.debug(f"No operator found in range part: {part}")
        
        return ranges
    
    @staticmethod
    def version_satisfies_constraint(
        version: pkg_version.Version,
        operator: str,
        constraint_version: pkg_version.Version
    ) -> bool:
        """
        Check if version satisfies a single constraint.
        
        Args:
            version: Version to check
            operator: Comparison operator (>=, <=, >, <, =, !=)
            constraint_version: Constraint version
        
        Returns:
            True if version satisfies constraint
        """
        if operator == ">=":
            return version >= constraint_version
        elif operator == "<=":
            return version <= constraint_version
        elif operator == ">":
            return version > constraint_version
        elif operator == "<":
            return version < constraint_version
        elif operator == "=" or operator == "==":
            return version == constraint_version
        elif operator == "!=":
            return version != constraint_version
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False
    
    @staticmethod
    def version_in_range(version_str: str, range_spec: str) -> bool:
        """
        Check if a version falls within a specified range.
        
        This is used to determine if a TuxCare patched version falls within
        the vulnerable version range reported by GitHub.
        
        Args:
            version_str: Version to check (e.g., "30.1-jre.tuxcare")
            range_spec: Range specification (e.g., ">= 25.0, < 32.0")
        
        Returns:
            True if version is in the range
        
        Example:
            version_in_range("30.1-jre.tuxcare", ">= 25.0, < 32.0") -> True
            version_in_range("30.1-jre.tuxcare", ">= 25.0, < 30.0") -> False
        """
        if not version_str or not range_spec:
            return False
        
        # Normalize version (strip .tuxcare suffix)
        normalized_version = VersionMatcher.normalize_version(version_str)
        
        # Parse version
        version = VersionMatcher.parse_version(normalized_version)
        if version is None:
            logger.debug(f"Could not parse version: {version_str}")
            return False
        
        # Parse range specification
        constraints = VersionMatcher.parse_range_spec(range_spec)
        if not constraints:
            logger.debug(f"No valid constraints in range: {range_spec}")
            return False
        
        # Check all constraints (AND logic)
        for operator, constraint_ver_str in constraints:
            constraint_ver = VersionMatcher.parse_version(constraint_ver_str)
            if constraint_ver is None:
                logger.debug(f"Could not parse constraint version: {constraint_ver_str}")
                continue
            
            if not VersionMatcher.version_satisfies_constraint(
                version, operator, constraint_ver
            ):
                return False
        
        return True
    
    @staticmethod
    def matches_alert(
        vex_version: str,
        alert_version_range: str,
        vex_package: str,
        alert_package: str
    ) -> bool:
        """
        Check if VEX package matches alert criteria.
        
        Args:
            vex_version: Version from VEX (e.g., "30.1-jre.tuxcare")
            alert_version_range: Vulnerable version range from alert
            vex_package: Package name from VEX (e.g., "com.google.guava:guava")
            alert_package: Package name from alert (e.g., "com.google.guava:guava")
        
        Returns:
            True if VEX entry matches the alert
        """
        # Package names must match
        if vex_package != alert_package:
            return False
        
        # VEX version should fall within vulnerable range
        # (meaning it's a patched version of a vulnerable version)
        return VersionMatcher.version_in_range(vex_version, alert_version_range)
    
    @staticmethod
    def extract_base_version(version_str: str) -> str:
        """
        Extract base version without TuxCare suffix.
        
        Args:
            version_str: Full version string
        
        Returns:
            Base version without .tuxcare suffix
        
        Example:
            "30.1-jre.tuxcare" -> "30.1-jre"
            "2.7.18.tuxcare.3" -> "2.7.18"
        """
        return VersionMatcher.normalize_version(version_str)

