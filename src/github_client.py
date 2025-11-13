"""GitHub GraphQL API client for TuxCare VEX Auto-Triage."""

import logging
import time
from typing import Dict, List, Optional, Any
import requests

from src.utils import GitHubAPIError, retry_with_backoff


logger = logging.getLogger("tuxcare-vex")


class GitHubClient:
    """Client for interacting with GitHub GraphQL API."""
    
    GRAPHQL_URL = "https://api.github.com/graphql"
    
    # GraphQL query for fetching vulnerability alerts
    ALERTS_QUERY = """
        query($owner: String!, $name: String!, $after: String) {
          repository(owner: $owner, name: $name) {
            vulnerabilityAlerts(first: 100, states: OPEN, after: $after) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                id
                number
                createdAt
                vulnerableManifestPath
                vulnerableRequirements
                securityVulnerability {
                  package {
                    ecosystem
                    name
                  }
                  vulnerableVersionRange
                }
                securityAdvisory {
                  ghsaId
                  identifiers {
                    type
                    value
                  }
                  publishedAt
                  severity
                  summary
                }
              }
            }
          }
        }
    """
    
    # GraphQL mutation for dismissing alerts
    DISMISS_MUTATION = """
        mutation($id: ID!) {
          dismissRepositoryVulnerabilityAlert(input: {
            repositoryVulnerabilityAlertId: $id,
            dismissReason: INACCURATE
          }) {
            repositoryVulnerabilityAlert {
              id
              dismissedAt
              dismissReason
            }
          }
        }
    """
    
    def __init__(self, token: str, repository: str):
        """
        Initialize GitHub client.
        
        Args:
            token: GitHub personal access token
            repository: Repository in format "owner/repo"
        """
        self.token = token
        self.repository = repository
        
        # Create session with auth
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        })
        
        # Rate limit tracking
        self._rate_limit_remaining: Optional[int] = None
        self._rate_limit_reset: Optional[int] = None
    
    @retry_with_backoff(
        max_retries=3,
        initial_delay=2.0,
        exceptions=(requests.RequestException,)
    )
    def gql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a GraphQL query.
        
        Args:
            query: GraphQL query string
            variables: Optional query variables
        
        Returns:
            Response data
        
        Raises:
            GitHubAPIError: If the request fails
        """
        payload = {
            "query": query,
            "variables": variables or {}
        }
        
        try:
            response = self.session.post(
                self.GRAPHQL_URL,
                json=payload,
                timeout=60
            )
            
            # Update rate limit info from headers
            self._update_rate_limit(response)
            
            if response.status_code != 200:
                raise GitHubAPIError(
                    f"GraphQL request failed with status {response.status_code}: "
                    f"{response.text}"
                )
            
            data = response.json()
            
            # Check for GraphQL errors
            if "errors" in data:
                error_messages = [e.get("message", str(e)) for e in data["errors"]]
                raise GitHubAPIError(f"GraphQL errors: {', '.join(error_messages)}")
            
            return data.get("data", {})
            
        except requests.Timeout as e:
            raise GitHubAPIError(f"Request timeout: {e}")
        except requests.RequestException as e:
            raise GitHubAPIError(f"Request failed: {e}")
    
    def _update_rate_limit(self, response: requests.Response) -> None:
        """Update rate limit info from response headers."""
        try:
            if "X-RateLimit-Remaining" in response.headers:
                self._rate_limit_remaining = int(response.headers["X-RateLimit-Remaining"])
            if "X-RateLimit-Reset" in response.headers:
                self._rate_limit_reset = int(response.headers["X-RateLimit-Reset"])
        except (ValueError, KeyError):
            pass
    
    def check_rate_limit(self) -> None:
        """
        Check rate limit and wait if necessary.
        
        If remaining requests are low (< 10), sleep until reset time.
        """
        if self._rate_limit_remaining is not None and self._rate_limit_remaining < 10:
            if self._rate_limit_reset:
                wait_time = self._rate_limit_reset - int(time.time())
                if wait_time > 0:
                    logger.warning(
                        f"Rate limit low ({self._rate_limit_remaining} remaining). "
                        f"Waiting {wait_time}s until reset..."
                    )
                    time.sleep(wait_time + 1)  # Add 1 second buffer
    
    def get_alerts(
        self,
        owner: str,
        repo: str,
        after: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Fetch vulnerability alerts for a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            after: Pagination cursor (optional)
        
        Returns:
            Response data with alerts and pagination info
        """
        self.check_rate_limit()
        
        variables = {
            "owner": owner,
            "name": repo,
            "after": after
        }
        
        logger.debug(f"Fetching alerts (after={after})")
        
        return self.gql(self.ALERTS_QUERY, variables)
    
    def dismiss_alert(self, alert_id: str, dry_run: bool = False) -> bool:
        """
        Dismiss a vulnerability alert.
        
        Args:
            alert_id: Alert ID to dismiss
            dry_run: If True, simulate dismissal without actually doing it
        
        Returns:
            True if successful (or if dry_run)
        
        Raises:
            GitHubAPIError: If dismissal fails
        """
        if dry_run:
            logger.info(f"[DRY-RUN] Would dismiss alert {alert_id}")
            return True
        
        self.check_rate_limit()
        
        variables = {"id": alert_id}
        
        try:
            result = self.gql(self.DISMISS_MUTATION, variables)
            
            # Verify dismissal was successful
            dismissed_alert = result.get("dismissRepositoryVulnerabilityAlert", {})
            dismissed_at = dismissed_alert.get("repositoryVulnerabilityAlert", {}).get("dismissedAt")
            
            if dismissed_at:
                logger.debug(f"Alert {alert_id} dismissed at {dismissed_at}")
                return True
            else:
                logger.warning(f"Alert {alert_id} dismissal response unclear")
                return False
                
        except GitHubAPIError as e:
            logger.error(f"Failed to dismiss alert {alert_id}: {e}")
            raise
    
    def get_all_alerts(
        self,
        owner: str,
        repo: str,
        max_alerts: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Fetch all open vulnerability alerts with pagination.
        
        Args:
            owner: Repository owner
            repo: Repository name
            max_alerts: Maximum number of alerts to fetch (0 = unlimited)
        
        Returns:
            List of alert objects
        """
        all_alerts: List[Dict[str, Any]] = []
        after = None
        page_count = 0
        
        while True:
            page_count += 1
            logger.info(f"Fetching alerts page {page_count}...")
            
            data = self.get_alerts(owner, repo, after)
            
            vulnerability_alerts = data.get("repository", {}).get("vulnerabilityAlerts", {})
            nodes = vulnerability_alerts.get("nodes", [])
            page_info = vulnerability_alerts.get("pageInfo", {})
            
            all_alerts.extend(nodes)
            
            logger.info(f"Fetched {len(nodes)} alerts (total: {len(all_alerts)})")
            
            # Check if we've reached the limit
            if max_alerts > 0 and len(all_alerts) >= max_alerts:
                logger.info(f"Reached max_alerts limit ({max_alerts})")
                all_alerts = all_alerts[:max_alerts]
                break
            
            # Check if there are more pages
            if not page_info.get("hasNextPage"):
                logger.info("No more pages to fetch")
                break
            
            after = page_info.get("endCursor")
            if not after:
                break
        
        return all_alerts
    
    @staticmethod
    def extract_cve(alert: Dict[str, Any]) -> Optional[str]:
        """
        Extract CVE identifier from alert.
        
        Args:
            alert: Alert object from GraphQL response
        
        Returns:
            CVE identifier (e.g., "CVE-2024-1234") or None
        """
        advisory = alert.get("securityAdvisory", {})
        identifiers = advisory.get("identifiers", [])
        
        for identifier in identifiers:
            if identifier.get("type", "").upper() == "CVE":
                return identifier.get("value")
        
        return None
    
    @staticmethod
    def get_package_info(alert: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract package information from alert.
        
        Args:
            alert: Alert object from GraphQL response
        
        Returns:
            Dictionary with ecosystem, name, version_range
        """
        vuln = alert.get("securityVulnerability", {})
        package = vuln.get("package", {})
        
        ecosystem = package.get("ecosystem", "")
        name = package.get("name", "")
        version_range = vuln.get("vulnerableVersionRange", "")
        
        return {
            "ecosystem": ecosystem,
            "name": name,
            "version_range": version_range
        }

