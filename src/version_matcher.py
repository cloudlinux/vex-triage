"""Version matching logic for TuxCare VEX Auto-Triage."""

import logging
import re

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
            "4.3.30.RELEASE-tuxcare.1" -> "4.3.30.RELEASE"
            "5.3.39.tuxcare1" -> "5.3.39"
        """
        if not version_str:
            return ""

        # Strip tuxcare suffix and any following version counter
        # Supports: .tuxcare.N, .tuxcare, -tuxcare.N, -tuxcare, .tuxcareN, -tuxcareN
        normalized = re.sub(r'[.-]tuxcare(\.?\d+)?$', '', version_str)

        return normalized

    @staticmethod
    def parse_version(version_str: str) -> pkg_version.Version | None:
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
    def parse_range_spec(range_spec: str) -> list[tuple[str, str]]:
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
        Check if version satisfies a single constraint using pattern matching.
        
        Args:
            version: Version to check
            operator: Comparison operator (>=, <=, >, <, =, !=)
            constraint_version: Constraint version
        
        Returns:
            True if version satisfies constraint
        """
        match operator:
            case ">=":
                return version >= constraint_version
            case "<=":
                return version <= constraint_version
            case ">":
                return version > constraint_version
            case "<":
                return version < constraint_version
            case "=" | "==":
                return version == constraint_version
            case "!=":
                return version != constraint_version
            case _:
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

    @staticmethod
    def extract_exact_version(version_requirement: str) -> str | None:
        """
        Extract exact version from a version requirement string.
        
        Maven, pip, npm, and composer may have version requirements like:
        - "= 1.2.17" or "1.2.17" (exact version)
        - "[1.2.17]" (Maven exact version)
        - "== 1.2.17" (pip exact version)
        - "^1.2.17" or "~1.2.17" (npm/composer range)
        
        This function tries to extract the exact version if present.
        
        Args:
            version_requirement: Version requirement string from manifest
        
        Returns:
            Exact version string if found, or the input string stripped of operators
        
        Example:
            "= 1.2.17" -> "1.2.17"
            "1.2.17" -> "1.2.17"
            "[1.2.17]" -> "1.2.17"
            ">= 1.2.0" -> "1.2.0" (may not be exact, but returns the constraint version)
        """
        if not version_requirement:
            return None

        req = version_requirement.strip()

        # Remove Maven brackets [version]
        if req.startswith('[') and req.endswith(']'):
            req = req[1:-1].strip()

        # Remove common operators and extract version
        # Handle: =, ==, >=, <=, >, <, ^, ~
        match = re.match(r'^[\^~><=!]*\s*(.+)$', req)
        if match:
            return match.group(1).strip()

        return req

    @staticmethod
    def versions_match(actual_version: str, vex_version: str) -> bool:
        """
        Check if the actual version used in repository matches the VEX patched version.
        
        The key insight: alerts should only be dismissed if the repository is actually using
        the TuxCare patched version. If the repo uses vanilla "1.2.17" and VEX has
        "1.2.17.tuxcare.1", they should NOT match because the repo doesn't have the patch.
        
        Matching logic:
        - If actual version has .tuxcare suffix: normalize both and compare base versions
        - If actual version does NOT have .tuxcare suffix: no match (repo not using patched version)
        
        Args:
            actual_version: Version requirement from manifest (may include operators)
            vex_version: TuxCare patched version from VEX (e.g., "1.2.17.tuxcare.1")
        
        Returns:
            True only if the repository is using a TuxCare patched version that matches VEX
        
        Example:
            versions_match("1.2.17", "1.2.17.tuxcare.1") -> False (repo not using TuxCare version)
            versions_match("1.2.17.tuxcare.1", "1.2.17.tuxcare.1") -> True (exact match)
            versions_match("1.2.17.tuxcare.1", "1.2.17.tuxcare.2") -> True (same base, different patch)
            versions_match("= 1.2.17.tuxcare.1", "1.2.17.tuxcare.1") -> True (with operator)
            versions_match("[1.2.17.tuxcare.1]", "1.2.17.tuxcare.1") -> True (Maven format)
        """
        if not actual_version or not vex_version:
            return False

        # Extract exact version from requirement (removes operators like =, >=, etc.)
        actual_clean = VersionMatcher.extract_exact_version(actual_version)
        if not actual_clean:
            return False

        # Check if the actual version has a .tuxcare suffix
        has_tuxcare_suffix = '.tuxcare' in actual_clean.lower() or '-tuxcare' in actual_clean.lower()

        if not has_tuxcare_suffix:
            # Repository is NOT using a TuxCare patched version
            # Therefore, it doesn't have the fix, and we should not dismiss the alert
            logger.debug(f"Actual version '{actual_clean}' does not have the tuxcare suffix - not using patched version")
            return False

        # Both versions have (or actual has) .tuxcare suffix
        # Normalize both versions (remove .tuxcare suffix and compare base versions)
        actual_normalized = VersionMatcher.normalize_version(actual_clean)
        vex_normalized = VersionMatcher.normalize_version(vex_version)

        # Parse both versions
        actual_ver = VersionMatcher.parse_version(actual_normalized)
        vex_ver = VersionMatcher.parse_version(vex_normalized)

        if actual_ver is None or vex_ver is None:
            # Fallback to string comparison if parsing fails
            logger.debug(f"Version parsing failed, using string comparison: {actual_normalized} vs {vex_normalized}")
            return actual_normalized.lower() == vex_normalized.lower()

        # Compare parsed versions
        return actual_ver == vex_ver
