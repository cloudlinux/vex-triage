"""GitHub GraphQL API client for TuxCare VEX Auto-Triage."""

import logging
import time
from typing import Any
import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

from src.utils import GitHubAPIError


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
        # Clean token of any whitespace or quotes
        self.token = token.strip().strip('"').strip("'")
        self.repository = repository
        
        # Log token info for debugging (without revealing the actual token)
        logger.debug(f"Token length: {len(self.token)}")
        if self.token:
            # Detect token type by prefix
            match self.token[:11] if len(self.token) >= 11 else self.token[:4]:
                case s if s.startswith('ghp_'):
                    logger.debug("Token type: Personal Access Token (classic)")
                case s if s.startswith('github_pat_'):
                    logger.debug("Token type: Fine-grained Personal Access Token")
                case s if s.startswith('ghs_'):
                    logger.debug("Token type: GitHub App installation token")
                case s if s.startswith('gho_'):
                    logger.debug("Token type: OAuth token")
                case s if s.startswith('ghu_'):
                    logger.debug("Token type: GitHub App user token")
                case s if s.startswith('v1.'):
                    logger.debug("Token type: GitHub Actions token (GITHUB_TOKEN)")
                case _:
                    logger.warning(f"Unknown token type (prefix: {self.token[:4]}...)")
        else:
            logger.error("Token is empty!")
        
        # Create session with auth
        # GitHub API accepts both "Bearer" and "token" prefix, but "Bearer" is preferred
        # for OAuth tokens and "token" for PATs. We'll use "Bearer" for all as it's more modern.
        # However, for GitHub Actions tokens specifically, let's try both if needed.
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        })
        
        # For debugging: also try with "token" prefix if Bearer fails
        self._auth_prefix = "Bearer"
        
        # Rate limit tracking
        self._rate_limit_remaining: int | None = None
        self._rate_limit_reset: int | None = None
    
    def check_token_permissions(self) -> dict[str, Any]:
        """
        Check what permissions the token has by querying the user endpoint.
        
        Returns:
            Dictionary with permission information
        """
        try:
            # First try with Bearer
            response = self.session.get("https://api.github.com/user", timeout=10)
            
            # If Bearer fails with 403, try legacy "token" format
            if response.status_code == 403:
                logger.debug("Bearer auth failed, trying legacy 'token' format...")
                headers = {
                    "Authorization": f"token {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                }
                response = requests.get("https://api.github.com/user", headers=headers, timeout=10)
                
                # If legacy format works, update the session to use it
                if response.status_code == 200:
                    logger.info("Using legacy 'token' auth format (Bearer didn't work)")
                    self.session.headers.update({"Authorization": f"token {self.token}"})
                    self._auth_prefix = "token"
            
            result = {
                "authenticated": response.status_code == 200,
                "status_code": response.status_code,
                "scopes": response.headers.get("X-OAuth-Scopes", ""),
                "user": response.json().get("login", "unknown") if response.status_code == 200 else None
            }
            
            # If still 403, provide detailed error
            if response.status_code == 403:
                try:
                    error_data = response.json()
                    result["error_message"] = error_data.get("message", "")
                    result["error_docs"] = error_data.get("documentation_url", "")
                    logger.error(f"Token authentication failed (403): {error_data.get('message', 'Unknown error')}")
                    logger.error("This usually means:")
                    logger.error("  1. The token is invalid or expired")
                    logger.error("  2. The token doesn't have the required permissions")
                    logger.error("  3. GitHub Actions GITHUB_TOKEN may have restricted access")
                except Exception:
                    logger.error("Token authentication failed (403): Unable to parse error response")
            
            logger.debug(f"Token check result: {result}")
            return result
            
        except Exception as e:
            logger.warning(f"Failed to check token permissions: {e}")
            return {"authenticated": False, "error": str(e)}
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(requests.RequestException),
        reraise=True
    )
    def gql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
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
        after: str | None = None
    ) -> dict[str, Any]:
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
    ) -> list[dict[str, Any]]:
        """
        Fetch all open vulnerability alerts with pagination.
        
        Args:
            owner: Repository owner
            repo: Repository name
            max_alerts: Maximum number of alerts to fetch (0 = unlimited)
        
        Returns:
            List of alert objects
        """
        all_alerts: list[dict[str, Any]] = []
        after = None
        page_count = 0
        
        while True:
            page_count += 1
            logger.info(f"Fetching alerts page {page_count}...")
            
            data = self.get_alerts(owner, repo, after)
            
            # Check if repository was found
            repository = data.get("repository")
            if repository is None:
                logger.error(f"Repository {owner}/{repo} not found or not accessible")
                logger.error("Possible causes:")
                logger.error("  1. Repository doesn't exist")
                logger.error("  2. Token doesn't have access to the repository")
                logger.error("  3. Repository name is incorrect")
                break
            
            vulnerability_alerts = repository.get("vulnerabilityAlerts")
            if vulnerability_alerts is None:
                logger.error("vulnerabilityAlerts field returned null")
                logger.error("Possible causes:")
                logger.error("  1. Token doesn't have 'security_events' scope/permission")
                logger.error("  2. Token doesn't have sufficient access (admin/maintain/write) to the repository")
                logger.error("  3. Dependabot alerts are not enabled on the repository")
                logger.error("")
                logger.error("To fix this:")
                logger.error("  - Ensure your workflow has 'permissions: security-events: write'")
                logger.error("  - Check that Dependabot alerts are enabled in repository settings")
                logger.error("  - Verify the token has access to security features")
                break
            
            nodes = vulnerability_alerts.get("nodes", [])
            page_info = vulnerability_alerts.get("pageInfo", {})
            
            all_alerts.extend(nodes)
            
            logger.info(f"Fetched {len(nodes)} alerts (total: {len(all_alerts)})")
            
            # Provide helpful information on first page if no alerts
            if page_count == 1 and len(nodes) == 0:
                logger.warning("No alerts found on first page")
                logger.info("If you expect alerts to exist:")
                logger.info("  1. Verify Dependabot alerts are enabled in Settings → Security → Code security")
                logger.info("  2. Check workflow permissions: security-events: write")
                logger.info("  3. Ensure token has access to security features")
                logger.info("  4. Run the debug script: python debug_permissions.py")
            
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
    def extract_cve(alert: dict[str, Any]) -> str | None:
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
    def get_package_info(alert: dict[str, Any]) -> dict[str, str]:
        """
        Extract package information from alert.
        
        Args:
            alert: Alert object from GraphQL response
        
        Returns:
            Dictionary with ecosystem, name, version_range, and actual_version
        """
        vuln = alert.get("securityVulnerability", {})
        package = vuln.get("package", {})
        
        ecosystem = package.get("ecosystem", "")
        name = package.get("name", "")
        version_range = vuln.get("vulnerableVersionRange", "")
        
        # Extract the actual version used in the repository from vulnerableRequirements
        # This contains the version constraint from the manifest (pom.xml, requirements.txt, etc.)
        actual_version = alert.get("vulnerableRequirements", "")
        
        return {
            "ecosystem": ecosystem,
            "name": name,
            "version_range": version_range,
            "actual_version": actual_version
        }
