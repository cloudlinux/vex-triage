"""Configuration management for TuxCare VEX Auto-Triage."""

import os
from typing import Dict, List


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


class Config:
    """Configuration loaded from environment variables."""
    
    # Supported ecosystems and their VEX URLs
    ECOSYSTEM_VEX_URLS: Dict[str, str] = {
        "java": "https://security.tuxcare.com/vex/cyclonedx/els_lang_java/vex.json",
        "python": "https://security.tuxcare.com/vex/cyclonedx/els_lang_python/vex.json",
        "javascript": "https://security.tuxcare.com/vex/cyclonedx/els_lang_javascript/vex.json",
        "php": "https://security.tuxcare.com/vex/cyclonedx/els_lang_php/vex.json",
    }
    
    # Map GitHub ecosystem names to package URL types
    GITHUB_TO_PURL_ECOSYSTEM: Dict[str, str] = {
        "MAVEN": "maven",
        "PIP": "pypi",
        "NPM": "npm",
        "COMPOSER": "composer",
    }
    
    # Map our ecosystem names to GitHub ecosystem names
    ECOSYSTEM_TO_GITHUB: Dict[str, str] = {
        "java": "MAVEN",
        "python": "PIP",
        "javascript": "NPM",
        "php": "COMPOSER",
    }
    
    def __init__(self):
        """Initialize configuration from environment variables."""
        self.ecosystems = self._parse_ecosystems()
        self.github_repository = self._get_required("GITHUB_REPOSITORY")
        self.github_token = self._get_required("INPUT_GITHUB-TOKEN")
        self.dry_run = self._get_bool("INPUT_DRY-RUN", False)
        self.max_alerts = self._get_int("INPUT_MAX-ALERTS", 0)
        self.verbosity = self._get_str("INPUT_VERBOSITY", "INFO").upper()
        
        # Validate verbosity level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        if self.verbosity not in valid_levels:
            raise ConfigurationError(
                f"Invalid verbosity level: {self.verbosity}. "
                f"Must be one of: {', '.join(valid_levels)}"
            )
        
        # Parse repository owner and name
        if "/" not in self.github_repository:
            raise ConfigurationError(
                f"Invalid GITHUB_REPOSITORY format: {self.github_repository}. "
                "Expected format: owner/repo"
            )
        self.repo_owner, self.repo_name = self.github_repository.split("/", 1)
    
    def _get_required(self, key: str) -> str:
        """Get a required environment variable."""
        value = os.environ.get(key)
        if not value:
            raise ConfigurationError(f"Required environment variable {key} is not set")
        return value
    
    def _get_str(self, key: str, default: str) -> str:
        """Get a string environment variable with default."""
        return os.environ.get(key, default)
    
    def _get_bool(self, key: str, default: bool) -> bool:
        """Get a boolean environment variable with default."""
        value = os.environ.get(key, "").lower()
        if not value:
            return default
        return value in ("true", "1", "yes", "y")
    
    def _get_int(self, key: str, default: int) -> int:
        """Get an integer environment variable with default."""
        value = os.environ.get(key, "")
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            raise ConfigurationError(
                f"Invalid integer value for {key}: {value}"
            )
    
    def _parse_ecosystems(self) -> List[str]:
        """Parse and validate ecosystems from input."""
        ecosystems_str = self._get_required("INPUT_ECOSYSTEMS")
        
        # Split by comma and strip whitespace
        ecosystems = [e.strip().lower() for e in ecosystems_str.split(",") if e.strip()]
        
        if not ecosystems:
            raise ConfigurationError("No ecosystems specified")
        
        # Validate each ecosystem
        invalid = [e for e in ecosystems if e not in self.ECOSYSTEM_VEX_URLS]
        if invalid:
            raise ConfigurationError(
                f"Invalid ecosystem(s): {', '.join(invalid)}. "
                f"Supported ecosystems: {', '.join(self.ECOSYSTEM_VEX_URLS.keys())}"
            )
        
        return ecosystems
    
    def get_vex_url(self, ecosystem: str) -> str:
        """Get VEX URL for a given ecosystem."""
        return self.ECOSYSTEM_VEX_URLS[ecosystem]
    
    def get_github_ecosystem(self, ecosystem: str) -> str:
        """Get GitHub ecosystem name for a given ecosystem."""
        return self.ECOSYSTEM_TO_GITHUB.get(ecosystem, "")
    
    def get_purl_ecosystem(self, github_ecosystem: str) -> str:
        """Get purl ecosystem type from GitHub ecosystem name."""
        return self.GITHUB_TO_PURL_ECOSYSTEM.get(github_ecosystem.upper(), "")

