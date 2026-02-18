"""Configuration management for TuxCare VEX Auto-Triage."""

from typing import Literal
from pydantic import Field, field_validator, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.utils import ConfigurationError


class Config(BaseSettings):
    """Configuration loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    # Supported ecosystems and their VEX URLs
    ECOSYSTEM_VEX_URLS: dict[str, str] = {
        "java": "https://security.tuxcare.com/vex/cyclonedx/els_lang_java/vex.json",
        "python": "https://security.tuxcare.com/vex/cyclonedx/els_lang_python/vex.json",
        "javascript": "https://security.tuxcare.com/vex/cyclonedx/els_lang_javascript/vex.json",
        "php": "https://security.tuxcare.com/vex/cyclonedx/els_lang_php/vex.json",
    }
    
    # Map GitHub ecosystem names to package URL types
    GITHUB_TO_PURL_ECOSYSTEM: dict[str, str] = {
        "MAVEN": "maven",
        "PIP": "pypi",
        "NPM": "npm",
        "COMPOSER": "composer",
    }
    
    # Map our ecosystem names to GitHub ecosystem names
    ECOSYSTEM_TO_GITHUB: dict[str, str] = {
        "java": "MAVEN",
        "python": "PIP",
        "javascript": "NPM",
        "php": "COMPOSER",
    }
    
    # Required fields
    github_repository: str = Field(alias="GITHUB_REPOSITORY")
    github_token: str = Field(alias="INPUT_TOKEN")
    ecosystems_str: str = Field(alias="INPUT_ECOSYSTEMS")
    
    # Optional fields with defaults
    dry_run: bool = Field(default=False, alias="INPUT_DRY-RUN")
    max_alerts: int = Field(default=0, alias="INPUT_MAX-ALERTS")
    verbosity: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", 
        alias="INPUT_VERBOSITY"
    )
    
    @field_validator("verbosity", mode="before")
    @classmethod
    def validate_verbosity(cls, v: str) -> str:
        """Ensure verbosity is uppercase."""
        if isinstance(v, str):
            return v.upper()
        return v
    
    @field_validator("github_repository")
    @classmethod
    def validate_repository_format(cls, v: str) -> str:
        """Validate repository format."""
        if "/" not in v:
            raise ValueError(
                f"Invalid GITHUB_REPOSITORY format: {v}. "
                "Expected format: owner/repo"
            )
        return v
    
    @field_validator("ecosystems_str")
    @classmethod
    def validate_ecosystems_not_empty(cls, v: str) -> str:
        """Validate ecosystems string is not empty."""
        if not v.strip():
            raise ValueError("No ecosystems specified")
        return v
    
    @computed_field  # type: ignore[misc]
    @property
    def ecosystems(self) -> list[str]:
        """Parse and validate ecosystems from input."""
        # Split by comma and strip whitespace
        ecosystems = [e.strip().lower() for e in self.ecosystems_str.split(",") if e.strip()]
        
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
    
    @computed_field  # type: ignore[misc]
    @property
    def repo_owner(self) -> str:
        """Extract repository owner from github_repository."""
        return self.github_repository.split("/", 1)[0]
    
    @computed_field  # type: ignore[misc]
    @property
    def repo_name(self) -> str:
        """Extract repository name from github_repository."""
        return self.github_repository.split("/", 1)[1]
    
    def get_vex_url(self, ecosystem: str) -> str:
        """Get VEX URL for a given ecosystem."""
        return self.ECOSYSTEM_VEX_URLS[ecosystem]
    
    def get_github_ecosystem(self, ecosystem: str) -> str:
        """Get GitHub ecosystem name for a given ecosystem."""
        return self.ECOSYSTEM_TO_GITHUB.get(ecosystem, "")
    
    def get_purl_ecosystem(self, github_ecosystem: str) -> str:
        """Get purl ecosystem type from GitHub ecosystem name."""
        return self.GITHUB_TO_PURL_ECOSYSTEM.get(github_ecosystem.upper(), "")
