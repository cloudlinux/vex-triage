# TuxCare VEX Auto-Triage

Automatically dismiss GitHub Dependabot security alerts based on TuxCare VEX (Vulnerability Exploitability eXchange) data.

## Overview

TuxCare provides Extended Lifecycle Support (ELS) for end-of-life software packages, including security patches for Java, Python, JavaScript, and PHP libraries. When using TuxCare's patched versions, you may still receive Dependabot alerts for vulnerabilities that have already been fixed in the TuxCare-maintained versions.

This GitHub Action bridges that gap by automatically dismissing alerts for vulnerabilities that TuxCare has marked as "resolved" in their VEX documentation, reducing alert fatigue and false positives.

## Features

- **Multi-ecosystem support**: Java (Maven), Python (pip), JavaScript (npm), PHP (Composer)
- **Smart version matching**: Compares vulnerable version ranges with TuxCare patched versions
- **Rate limiting**: Respects GitHub API rate limits with automatic backoff
- **Dry-run mode**: Test the action without actually dismissing alerts
- **Comprehensive logging**: Detailed logs with GitHub Actions annotations
- **Fresh data**: Fetches latest VEX data on every run (no stale cache issues)
- **Retry logic**: Exponential backoff for transient failures

## Prerequisites

Before using this action, you need to:

### 1. Enable Dependabot Security Updates

Enable Dependabot in your repository to receive security alerts:

1. Go to your repository on GitHub
2. Click **Settings** → **Advanced Security**
3. Enable **Dependabot alerts** (if not already enabled)
4. Enable **Dependabot security updates** (optional, but recommended)

### 2. Verify Active Alerts

Check that you have Dependabot alerts:

1. Go to your repository's **Security** tab
2. Click **Dependabot** in the left sidebar
3. You should see a list of open vulnerability alerts
4. Note the ecosystems (Maven, pip, npm, Composer) of your alerts

If you have no alerts, Dependabot hasn't found any vulnerabilities in your dependencies.

### 3. Create a Personal Access Token (PAT)

This action requires a **Personal Access Token (PAT)** with the appropriate permissions to access and dismiss Dependabot alerts.

**Create a PAT:**

1. Go to GitHub **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
2. Click **Generate new token** → **Generate new token (classic)**
3. Configure the token:
   - **Note**: `VEX Auto-Triage`
   - **Expiration**: 90 days or custom (set a calendar reminder to regenerate)
   - **Select Scopes**:
     - **repo** (selects all sub-items of `repo`)

4. Click **Generate token** and copy it immediately

**Add token to repository secrets:**

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `VEX_TRIAGE_TOKEN`
4. Value: Paste your PAT
5. Click **Add secret**

### 4. Check Dismissed Alerts After Running

After the action runs (you may run it manually), verify alerts were dismissed:

1. Go to **Security** → **Dependabot**
2. Click the **Closed** tab at the top
3. Each dismissal will show:
   - The bot that dismissed it (dependabot)
   - Timestamp
   - Link to the related code snippet

You can also check the action's output in the **Actions** tab to see a summary of dismissed alerts.

## Quick Start

Add this workflow to your repository at `.github/workflows/vex-triage.yml`:

```yaml
name: TuxCare VEX Auto-Triage

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:      # Manual trigger

jobs:
  triage:
    runs-on: ubuntu-latest
    
    steps:
      - name: Run TuxCare VEX Auto-Triage
        uses: anayden/tuxcare-workflow@main
        with:
          ecosystems: 'java,python'
          token: ${{ secrets.VEX_TRIAGE_TOKEN }}
```

## Configuration

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `ecosystems` | Yes | - | Comma-separated list of ecosystems to process: `java`, `python`, `javascript`, `php` |
| `token` | Yes | - | Personal Access Token (PAT) with `repo` permission, stored in secrets (e.g., `${{ secrets.VEX_TRIAGE_TOKEN }}`). See [Prerequisites](#3-create-a-personal-access-token-pat) for setup. |
| `dry-run` | No | `false` | If `true`, simulates dismissals without actually dismissing alerts |
| `max-alerts` | No | `0` | Maximum number of alerts to process (0 = unlimited, useful for testing) |
| `verbosity` | No | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Required Permissions

Your Personal Access Token (PAT) must have the `repo` permissions:

See [Prerequisites](#3-create-a-personal-access-token-pat) for detailed instructions on creating a PAT with these permissions.

## Usage Examples

### Basic Usage - Single Ecosystem

```yaml
- uses: anayden/tuxcare-workflow@main
  with:
    ecosystems: 'java'
    token: ${{ secrets.VEX_TRIAGE_TOKEN }}
```

### Multiple Ecosystems

```yaml
- uses: anayden/tuxcare-workflow@main
  with:
    ecosystems: 'java,python,javascript,php'
    token: ${{ secrets.VEX_TRIAGE_TOKEN }}
```

### Dry-Run Mode (Testing)

Test the action without dismissing alerts:

```yaml
- uses: anayden/tuxcare-workflow@main
  with:
    ecosystems: 'java'
    token: ${{ secrets.VEX_TRIAGE_TOKEN }}
    dry-run: 'true'
    verbosity: 'DEBUG'
```

### Limited Processing for Testing

Process only the first 10 alerts:

```yaml
- uses: anayden/tuxcare-workflow@main
  with:
    ecosystems: 'java'
    token: ${{ secrets.VEX_TRIAGE_TOKEN }}
    max-alerts: '10'
```

### Manual Trigger Only

```yaml
name: Manual VEX Triage

on:
  workflow_dispatch:
    inputs:
      dry_run:
        description: 'Dry run mode'
        required: false
        default: 'false'
        type: choice
        options:
          - 'true'
          - 'false'

jobs:
  triage:
    runs-on: ubuntu-latest
    
    steps:
      - uses: anayden/tuxcare-workflow@main
        with:
          ecosystems: 'java,python'
          token: ${{ secrets.VEX_TRIAGE_TOKEN }}
          dry-run: ${{ inputs.dry_run }}
```

## How It Works

### Process Flow

1. **Fetch VEX Data**: Downloads latest VEX files from TuxCare for selected ecosystems
2. **Index CVEs**: Parses VEX data into efficient lookup structures
3. **Fetch Alerts**: Retrieves all open Dependabot security alerts from GitHub
4. **Match & Triage**: For each alert:
   - Extracts CVE identifier
   - Checks if CVE exists in VEX data
   - Verifies package name matches
   - Confirms vulnerability is marked as "resolved"
   - Validates version compatibility
   - Dismisses alert if all checks pass
5. **Report Results**: Outputs summary with dismissed and skipped alerts

### Version Matching

The action uses **exact version matching** to ensure accuracy and prevent false dismissals:

1. **Extract actual version**: Gets the exact version from your manifest (pom.xml, requirements.txt, etc.)
2. **Check TuxCare suffix**: Verifies the actual version has the `tuxcare` suffix
3. **Compare base versions**: If using TuxCare version, compares the base version with VEX data
4. **Validate**: Confirms the fix applies to the specific package and CVE

**Critical**: Alerts are only dismissed if your repository is using the TuxCare patched version (with `tuxcare` suffix), not just because a patched version exists in VEX.

### Example Scenarios

#### Scenario 1: Using Vanilla Version (Alert NOT Dismissed)

**Your pom.xml**: `log4j:log4j:1.2.17`

**Alert**: CVE-2021-4104 in log4j affecting `>= 1.2.0, <= 1.2.17`

**VEX Data**: TuxCare has `log4j@1.2.17.tuxcare.1` marked as "resolved"

**Action**:
1. Extracts actual version: `1.2.17` (no `.tuxcare` suffix)
2. Recognizes repository is NOT using TuxCare patched version
3. **Skips dismissal** - you don't have the fix

#### Scenario 2: Using TuxCare Version (Alert Dismissed)

**Your pom.xml**: `log4j:log4j:1.2.17.tuxcare.1`

**Alert**: CVE-2021-4104 in log4j affecting `>= 1.2.0, <= 1.2.17`

**VEX Data**: TuxCare has `log4j@1.2.17.tuxcare.1` marked as "resolved"

**Action**:
1. Extracts actual version: `1.2.17.tuxcare.1` (has `.tuxcare` suffix) ✓
2. Normalizes both versions: `1.2.17` == `1.2.17` ✓
3. Verifies package name matches ✓
4. Confirms state is "resolved" ✓
5. **Dismisses the alert** - you have the fix

## VEX Data Sources

The action fetches VEX data from TuxCare's public endpoints:

- **Java**: https://security.tuxcare.com/vex/cyclonedx/els_lang_java/vex.json
- **Python**: https://security.tuxcare.com/vex/cyclonedx/els_lang_python/vex.json
- **JavaScript**: https://security.tuxcare.com/vex/cyclonedx/els_lang_javascript/vex.json
- **PHP**: https://security.tuxcare.com/vex/cyclonedx/els_lang_php/vex.json

VEX data is fetched fresh on every run to ensure you're always working with the latest information.

## Output

### JSON Summary

The action outputs a JSON summary with detailed statistics:

```json
{
  "total_alerts": 50,
  "dismissed_count": 8,
  "dismissed": [
    {
      "number": 42,
      "package": "com.google.guava:guava",
      "cve": "CVE-2020-8908",
      "tuxcare_version": "30.1-jre.tuxcare",
      "vex_package": "com.google.guava:guava"
    }
  ],
  "skipped_count": 42,
  "skipped_by_reason": {
    "ecosystem-not-selected": 20,
    "cve-not-in-vex": 15,
    "no-positive-vex-match": 7
  },
  "ecosystems_processed": ["java", "python"],
  "execution_time_seconds": 12.5
}
```

### GitHub Actions Summary

Results are also displayed in the GitHub Actions UI as a step summary with tables showing:

- Overview statistics
- List of dismissed alerts
- Breakdown of skip reasons
- Execution time

### Annotations

The action creates GitHub Actions annotations for:

- **Notices**: Successfully dismissed alerts
- **Warnings**: Rate limiting or retries
- **Errors**: Configuration or API errors

## Skip Reasons

Alerts may be skipped for various reasons:

| Reason | Description |
|--------|-------------|
| `no-cve` | No CVE identifier found in alert |
| `unsupported-ecosystem` | Ecosystem not supported by action |
| `ecosystem-not-selected` | Ecosystem not in selected list |
| `no-vex-data` | Failed to load VEX data for ecosystem |
| `cve-not-in-vex` | CVE not found in VEX data |
| `no-actual-version` | Cannot determine actual version from manifest |
| `no-positive-vex-match` | Repository not using TuxCare patched version |
| `invalid-package` | Package name format invalid |
| `dismiss-failed` | API call to dismiss alert failed |

## Troubleshooting

### No Alerts Found (0 Alerts Returned)

If the action reports 0 alerts but you can see alerts in the GitHub UI, this is almost always a **permissions issue**.

**Solutions:**

1. **Verify your PAT has the correct permissions**:
   - Follow the [Prerequisites](#3-create-a-personal-access-token-pat) section to create a properly configured PAT
   - Ensure the token has `Security events: Read and write` permission
   - Verify the token has access to your repository
   - Confirm the secret is named correctly in your workflow (e.g., `VEX_TRIAGE_TOKEN`)

2. **Verify Dependabot is enabled**:
   - See [Prerequisites](#1-enable-dependabot-security-updates) section
   - Check that alerts are visible in Security → Dependabot alerts
   - Ensure you have open (not closed) alerts

### No Alerts Dismissed

**Possible causes:**

1. **VEX data doesn't cover your packages**: TuxCare VEX only includes packages they provide ELS for
2. **Version mismatch**: Your package version might not match TuxCare's patched version
3. **Wrong ecosystem selected**: Ensure you've selected the correct ecosystems

**Solution**: Run with `dry-run: true` and `verbosity: DEBUG` to see detailed matching logic.

### Rate Limiting

The action automatically handles rate limiting, but if you hit limits:

- The action will wait until the rate limit resets
- Consider running less frequently (e.g., daily instead of hourly)
- Check your organization's rate limits

### VEX Fetch Failures

If VEX data fails to download:

- The action will retry up to 3 times with exponential backoff
- Check TuxCare's status page for service issues
- Verify network connectivity from GitHub Actions

## Security Considerations

### Trust Model

This action implicitly trusts TuxCare VEX data as authoritative. Dismissed alerts can always be manually re-opened if needed.

### Dismissal Reason

Alerts are dismissed with reason "INACCURATE" (GitHub doesn't have a "PATCHED" reason). GitHub maintains a full audit trail with timestamps.

### Reversibility

- All dismissed alerts can be manually re-opened in the GitHub Security tab
- GitHub maintains full history of dismissals
- Dry-run mode allows testing without side effects

## Limitations

1. **Ecosystem coverage**: Only Maven, pip, npm, and Composer are supported
2. **VEX dependency**: Requires TuxCare VEX data for your packages
3. **API rate limits**: Subject to GitHub GraphQL API limits (typically 5000/hour)

## Support

### TuxCare VEX Documentation

- Website: https://tuxcare.com/
- VEX Repository: https://security.tuxcare.com/vex/
- Support: support@tuxcare.com

### GitHub Dependabot

- Documentation: https://docs.github.com/en/code-security/dependabot

### Action Issues

For issues with this action:
- GitHub Issues: https://github.com/anayden/tuxcare-workflow/issues
- Check logs with `verbosity: DEBUG`
- Test with `dry-run: true` first

## Development

This project uses modern Python tooling with [uv](https://github.com/astral-sh/uv) for fast dependency management and `pyproject.toml` for configuration.

### Quick Setup

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone <repo-url>
cd tuxcare-vex

# Create virtual environment and install dependencies (10x faster than pip!)
uv venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows
uv pip install -e ".[dev]"
```

### Adding Dependencies

**Production dependency:**
```toml
# Edit pyproject.toml [project.dependencies]
dependencies = [
    "new-package>=1.0.0",
]
```

**Development dependency:**
```toml
# Edit pyproject.toml [project.optional-dependencies.dev]
[project.optional-dependencies]
dev = [
    "new-dev-tool>=1.0.0",
]
```

Then install:
```bash
uv pip install -e ".[dev]"
```

### Python Version

This project requires **Python 3.11+** for modern features:
- PEP 604: Union types with `|` operator
- PEP 634: Structural pattern matching
- Better error messages and performance

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run tests and linting: `./run_tests.sh`
5. Submit a pull request

### Development Guidelines

- Use modern Python 3.11+ features (type hints, pattern matching)
- Add tests for all new functionality
- Keep test coverage high
- Follow existing code style (black + ruff)
- Update documentation for user-facing changes

## License

See [LICENSE](LICENSE) file for details.