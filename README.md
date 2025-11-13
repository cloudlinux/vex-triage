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
    permissions:
      contents: read
      security-events: write
    
    steps:
      - name: Run TuxCare VEX Auto-Triage
        uses: tuxcare/vex-auto-triage@v1
        with:
          ecosystems: 'java,python'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Configuration

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `ecosystems` | Yes | - | Comma-separated list of ecosystems to process: `java`, `python`, `javascript`, `php` |
| `github-token` | Yes | - | GitHub token with `security_events` write permission |
| `dry-run` | No | `false` | If `true`, simulates dismissals without actually dismissing alerts |
| `max-alerts` | No | `0` | Maximum number of alerts to process (0 = unlimited, useful for testing) |
| `verbosity` | No | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Permissions

The action requires the following permissions:

```yaml
permissions:
  contents: read          # To access repository
  security-events: write  # To dismiss alerts
```

## Usage Examples

### Basic Usage - Single Ecosystem

```yaml
- uses: tuxcare/vex-auto-triage@v1
  with:
    ecosystems: 'java'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Multiple Ecosystems

```yaml
- uses: tuxcare/vex-auto-triage@v1
  with:
    ecosystems: 'java,python,javascript,php'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Dry-Run Mode (Testing)

Test the action without dismissing alerts:

```yaml
- uses: tuxcare/vex-auto-triage@v1
  with:
    ecosystems: 'java'
    github-token: ${{ secrets.GITHUB_TOKEN }}
    dry-run: 'true'
    verbosity: 'DEBUG'
```

### Limited Processing for Testing

Process only the first 10 alerts:

```yaml
- uses: tuxcare/vex-auto-triage@v1
  with:
    ecosystems: 'java'
    github-token: ${{ secrets.GITHUB_TOKEN }}
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
    permissions:
      contents: read
      security-events: write
    
    steps:
      - uses: tuxcare/vex-auto-triage@v1
        with:
          ecosystems: 'java,python'
          github-token: ${{ secrets.GITHUB_TOKEN }}
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

The action uses smart version matching to ensure accuracy:

1. **Normalize versions**: Strips `.tuxcare` suffix from versions
2. **Parse ranges**: Interprets GitHub's vulnerable version ranges (e.g., `>= 25.0, < 32.0`)
3. **Compare**: Checks if TuxCare's patched version falls within the vulnerable range
4. **Validate**: Confirms the fix applies to the specific package and CVE

### Example Scenario

**Alert**: Guava vulnerability CVE-2020-8908 in version range `>= 25.0, < 32.0`

**VEX Data**: TuxCare has `guava@30.1-jre.tuxcare` marked as "resolved" for CVE-2020-8908

**Action**:
1. Normalizes `30.1-jre.tuxcare` → `30.1-jre`
2. Checks `30.1-jre` is in range `>= 25.0, < 32.0` ✓
3. Verifies package name matches ✓
4. Confirms state is "resolved" ✓
5. **Dismisses the alert**

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
| `no-positive-vex-match` | No resolved VEX entry matches alert criteria |
| `invalid-package` | Package name format invalid |
| `dismiss-failed` | API call to dismiss alert failed |

## Troubleshooting

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

### Permission Errors

**Error**: `Resource not accessible by integration`

**Solution**: Ensure your workflow has the required permissions:

```yaml
permissions:
  security-events: write
```

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

### Token Permissions

The provided token must have `security_events` write permission. Use `${{ secrets.GITHUB_TOKEN }}` which is automatically scoped to the repository.

### Reversibility

- All dismissed alerts can be manually re-opened in the GitHub Security tab
- GitHub maintains full history of dismissals
- Dry-run mode allows testing without side effects

## Limitations

1. **Ecosystem coverage**: Only Maven, pip, npm, and Composer are supported
2. **VEX dependency**: Requires TuxCare VEX data for your packages
3. **No version checking for unpublished versions**: Action assumes VEX URLs are correct
4. **API rate limits**: Subject to GitHub GraphQL API limits (typically 5000/hour)

## Support

### TuxCare VEX Documentation

- Website: https://tuxcare.com/
- VEX Repository: https://security.tuxcare.com/vex/
- Support: support@tuxcare.com

### GitHub Dependabot

- Documentation: https://docs.github.com/en/code-security/dependabot

### Action Issues

For issues with this action:
- GitHub Issues: https://github.com/tuxcare/vex-auto-triage/issues
- Check logs with `verbosity: DEBUG`
- Test with `dry-run: true` first

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

See [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

