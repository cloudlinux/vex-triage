"""Alert triage engine for TuxCare VEX Auto-Triage."""

import logging
from typing import Dict, List, Any
from collections import defaultdict

from src.config import Config
from src.github_client import GitHubClient
from src.vex_client import VexClient
from src.version_matcher import VersionMatcher
from src.utils import github_notice


logger = logging.getLogger("tuxcare-vex")


class TriageEngine:
    """Engine for processing and triaging vulnerability alerts."""
    
    def __init__(
        self,
        config: Config,
        github_client: GitHubClient,
        vex_clients: Dict[str, VexClient]
    ):
        """
        Initialize triage engine.
        
        Args:
            config: Configuration object
            github_client: GitHub API client
            vex_clients: Dictionary mapping ecosystem -> VexClient
        """
        self.config = config
        self.github_client = github_client
        self.vex_clients = vex_clients
        
        # Statistics
        self.dismissed: List[Dict[str, Any]] = []
        self.skipped: List[Dict[str, Any]] = []
        self.skip_reasons = defaultdict(int)
    
    def triage_alerts(self) -> Dict[str, Any]:
        """
        Main triage loop: fetch alerts, check VEX, dismiss if resolved.
        
        Returns:
            Summary dictionary with statistics
        """
        logger.info("=" * 60)
        logger.info("Starting TuxCare VEX Auto-Triage")
        logger.info("=" * 60)
        logger.info(f"Repository: {self.config.github_repository}")
        logger.info(f"Ecosystems: {', '.join(self.config.ecosystems)}")
        logger.info(f"Dry-run: {self.config.dry_run}")
        logger.info(f"Max alerts: {self.config.max_alerts if self.config.max_alerts > 0 else 'unlimited'}")
        logger.info("=" * 60)
        
        # Pre-fetch and parse VEX data for all ecosystems
        logger.info("\n[PHASE 1] Fetching VEX data...")
        vex_data = self._fetch_vex_data()
        
        # Fetch all alerts
        logger.info("\n[PHASE 2] Fetching GitHub alerts...")
        alerts = self.github_client.get_all_alerts(
            self.config.repo_owner,
            self.config.repo_name,
            self.config.max_alerts
        )
        
        logger.info(f"Found {len(alerts)} open alerts to process")
        
        # Process each alert
        logger.info("\n[PHASE 3] Processing alerts...")
        for i, alert in enumerate(alerts, 1):
            logger.info(f"\n--- Alert {i}/{len(alerts)} ---")
            self._process_alert(alert, vex_data)
        
        # Generate summary
        logger.info("\n[PHASE 4] Generating summary...")
        summary = self._generate_summary()
        
        return summary
    
    def _fetch_vex_data(self) -> Dict[str, Dict[str, Any]]:
        """
        Fetch and parse VEX data for all configured ecosystems.
        
        Returns:
            Dictionary mapping ecosystem -> parsed VEX data
        """
        vex_data = {}
        
        for ecosystem in self.config.ecosystems:
            logger.info(f"\nFetching VEX for ecosystem: {ecosystem}")
            
            if ecosystem not in self.vex_clients:
                logger.warning(f"No VEX client for ecosystem: {ecosystem}")
                continue
            
            try:
                client = self.vex_clients[ecosystem]
                data = client.fetch_and_parse()
                vex_data[ecosystem] = data
                
                cve_count = len(data.get("cve_index", {}))
                logger.info(f"✓ Loaded VEX for {ecosystem}: {cve_count} CVEs indexed")
                
            except Exception as e:
                logger.error(f"✗ Failed to fetch VEX for {ecosystem}: {e}")
        
        return vex_data
    
    def _process_alert(self, alert: Dict[str, Any], vex_data: Dict[str, Dict[str, Any]]) -> None:
        """
        Process a single alert: check VEX and dismiss if resolved.
        
        Args:
            alert: Alert object from GitHub
            vex_data: Parsed VEX data for all ecosystems
        """
        alert_number = alert.get("number", "unknown")
        alert_id = alert.get("id", "")
        
        logger.info(f"Processing alert #{alert_number}")
        
        # Extract CVE
        cve = GitHubClient.extract_cve(alert)
        if not cve:
            self._skip_alert(alert_number, "no-cve", "No CVE identifier found")
            return
        
        logger.info(f"  CVE: {cve}")
        
        # Extract package info
        pkg_info = GitHubClient.get_package_info(alert)
        ecosystem = pkg_info["ecosystem"]
        package_name = pkg_info["name"]
        version_range = pkg_info["version_range"]
        
        logger.info(f"  Package: {package_name}")
        logger.info(f"  Ecosystem: {ecosystem}")
        logger.info(f"  Vulnerable range: {version_range}")
        
        # Validate package name format
        if not package_name:
            self._skip_alert(alert_number, "invalid-package", "Empty package name")
            return
        
        # Map GitHub ecosystem to our ecosystem
        our_ecosystem = self._map_github_ecosystem(ecosystem)
        if not our_ecosystem:
            self._skip_alert(alert_number, "unsupported-ecosystem", f"Ecosystem {ecosystem} not supported")
            return
        
        # Check if ecosystem is in our selected list
        if our_ecosystem not in self.config.ecosystems:
            self._skip_alert(
                alert_number,
                "ecosystem-not-selected",
                f"Ecosystem {our_ecosystem} not in selected ecosystems"
            )
            return
        
        # Check if we have VEX data for this ecosystem
        if our_ecosystem not in vex_data:
            self._skip_alert(alert_number, "no-vex-data", f"No VEX data loaded for {our_ecosystem}")
            return
        
        # Look up CVE in VEX
        vex_ecosystem_data = vex_data[our_ecosystem]
        cve_index = vex_ecosystem_data.get("cve_index", {})
        
        if cve not in cve_index:
            self._skip_alert(alert_number, "cve-not-in-vex", f"CVE {cve} not found in VEX")
            return
        
        # Check if any VEX packages match this alert
        vex_packages = cve_index[cve]
        logger.info(f"  Found {len(vex_packages)} VEX entries for {cve}")
        
        matched = False
        for vex_pkg in vex_packages:
            vex_full_name = vex_pkg.get("full_name", "")
            vex_version = vex_pkg.get("version", "")
            vex_state = vex_pkg.get("state", "")
            
            logger.debug(f"    Checking VEX package: {vex_full_name} @ {vex_version} (state: {vex_state})")
            
            # Check if package names match
            if not self._package_names_match(package_name, vex_full_name, ecosystem):
                logger.debug(f"    Package name mismatch: {package_name} != {vex_full_name}")
                continue
            
            # Check if state is resolved
            if vex_state != "resolved":
                logger.debug(f"    State is not resolved: {vex_state}")
                continue
            
            # Check if VEX version matches vulnerable range
            if version_range and not VersionMatcher.version_in_range(vex_version, version_range):
                logger.debug(f"    Version mismatch: {vex_version} not in range {version_range}")
                continue
            
            # We have a match!
            matched = True
            logger.info(f"  ✓ Match found: {vex_full_name} @ {vex_version} (resolved)")
            
            # Dismiss the alert
            self._dismiss_alert(alert, cve, package_name, vex_version, vex_full_name)
            break
        
        if not matched:
            self._skip_alert(
                alert_number,
                "no-positive-vex-match",
                f"No resolved VEX entry matches alert criteria"
            )
    
    def _map_github_ecosystem(self, github_ecosystem: str) -> str:
        """
        Map GitHub ecosystem name to our ecosystem name.
        
        Args:
            github_ecosystem: GitHub ecosystem (e.g., "MAVEN")
        
        Returns:
            Our ecosystem name (e.g., "java") or empty string if not found
        """
        for our_eco, gh_eco in self.config.ECOSYSTEM_TO_GITHUB.items():
            if gh_eco.upper() == github_ecosystem.upper():
                return our_eco
        return ""
    
    def _package_names_match(self, alert_name: str, vex_name: str, ecosystem: str) -> bool:
        """
        Check if package names match, accounting for different formats.
        
        Args:
            alert_name: Package name from alert
            vex_name: Package name from VEX
            ecosystem: Ecosystem type
        
        Returns:
            True if names match
        """
        # Normalize for comparison
        alert_normalized = alert_name.strip().lower()
        vex_normalized = vex_name.strip().lower()
        
        # Direct match
        if alert_normalized == vex_normalized:
            return True
        
        # For Maven, try different separators
        if ecosystem.upper() == "MAVEN":
            # Alert might use "/" while VEX uses ":"
            alert_colon = alert_normalized.replace("/", ":")
            vex_colon = vex_normalized.replace("/", ":")
            if alert_colon == vex_colon:
                return True
        
        return False
    
    def _dismiss_alert(
        self,
        alert: Dict[str, Any],
        cve: str,
        package_name: str,
        vex_version: str,
        vex_full_name: str
    ) -> None:
        """
        Dismiss an alert and record the action.
        
        Args:
            alert: Alert object
            cve: CVE identifier
            package_name: Package name from alert
            vex_version: TuxCare version from VEX
            vex_full_name: Full package name from VEX
        """
        alert_number = alert.get("number", "unknown")
        alert_id = alert.get("id", "")
        
        try:
            success = self.github_client.dismiss_alert(alert_id, self.config.dry_run)
            
            if success:
                dismissal = {
                    "number": alert_number,
                    "package": package_name,
                    "cve": cve,
                    "tuxcare_version": vex_version,
                    "vex_package": vex_full_name
                }
                self.dismissed.append(dismissal)
                
                if self.config.dry_run:
                    logger.info(f"  [DRY-RUN] Would dismiss alert #{alert_number}")
                else:
                    logger.info(f"  ✓ Dismissed alert #{alert_number}")
                    github_notice(
                        f"Dismissed alert #{alert_number}: {cve} in {package_name} "
                        f"(resolved in {vex_version})"
                    )
            else:
                self._skip_alert(alert_number, "dismiss-failed", "Dismissal returned false")
                
        except Exception as e:
            logger.error(f"  ✗ Failed to dismiss alert #{alert_number}: {e}")
            self._skip_alert(alert_number, "dismiss-error", str(e))
    
    def _skip_alert(self, alert_number: Any, reason: str, detail: str) -> None:
        """
        Record a skipped alert.
        
        Args:
            alert_number: Alert number
            reason: Skip reason code
            detail: Human-readable detail
        """
        logger.info(f"  → Skipped: {detail}")
        
        self.skipped.append({
            "number": alert_number,
            "reason": reason,
            "detail": detail
        })
        self.skip_reasons[reason] += 1
    
    def _generate_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics.
        
        Returns:
            Summary dictionary
        """
        total = len(self.dismissed) + len(self.skipped)
        
        summary = {
            "total_alerts": total,
            "dismissed_count": len(self.dismissed),
            "dismissed": self.dismissed,
            "skipped_count": len(self.skipped),
            "skipped": self.skipped,
            "skipped_by_reason": dict(self.skip_reasons),
            "ecosystems_processed": self.config.ecosystems,
            "dry_run": self.config.dry_run
        }
        
        # Log summary
        logger.info("\n" + "=" * 60)
        logger.info("SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total alerts processed: {total}")
        logger.info(f"Dismissed: {len(self.dismissed)}")
        logger.info(f"Skipped: {len(self.skipped)}")
        
        if self.skip_reasons:
            logger.info("\nSkip reasons breakdown:")
            for reason, count in sorted(self.skip_reasons.items()):
                logger.info(f"  - {reason}: {count}")
        
        if self.dismissed:
            logger.info("\nDismissed alerts:")
            for d in self.dismissed:
                logger.info(f"  - #{d['number']}: {d['cve']} in {d['package']}")
        
        logger.info("=" * 60)
        
        return summary

