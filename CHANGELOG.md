# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-13

### Added
- Initial release of TuxCare VEX Auto-Triage GitHub Action
- Support for Java (Maven), Python (pip), JavaScript (npm), and PHP (Composer) ecosystems
- Automatic dismissal of Dependabot alerts based on TuxCare VEX data
- Version range matching for accurate triage
- In-memory caching to avoid redundant VEX downloads
- Comprehensive logging and error handling
- Dry-run mode for testing
- GitHub Actions annotations and step summaries
- Rate limiting for GitHub API
- Retry logic with exponential backoff

