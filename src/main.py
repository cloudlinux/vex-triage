"""Main entry point for TuxCare VEX Auto-Triage GitHub Action."""

import sys
import json
import time
import traceback
from typing import Any

from src.config import Config
from src.utils import setup_logging, github_error, format_duration, ConfigurationError
from src.github_client import GitHubClient
from src.vex_client import VexClient
from src.triage import TriageEngine


def create_github_step_summary(summary: dict[str, Any]) -> None:
    """
    Create GitHub Actions step summary with results.
    
    Args:
        summary: Summary dictionary from triage engine
    """
    try:
        # Check if GITHUB_STEP_SUMMARY is set
        import os
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_file:
            return
        
        with open(summary_file, "a") as f:
            f.write("# TuxCare VEX Auto-Triage Results\n\n")
            
            # Overview table
            f.write("## Overview\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Total Alerts | {summary['total_alerts']} |\n")
            f.write(f"| Dismissed | {summary['dismissed_count']} |\n")
            f.write(f"| Skipped | {summary['skipped_count']} |\n")
            f.write(f"| Ecosystems | {', '.join(summary['ecosystems_processed'])} |\n")
            f.write(f"| Dry Run | {'Yes' if summary['dry_run'] else 'No'} |\n")
            f.write("\n")
            
            # Dismissed alerts
            if summary['dismissed']:
                f.write("## Dismissed Alerts\n\n")
                f.write("| Alert # | CVE | Package | TuxCare Version |\n")
                f.write("|---------|-----|---------|----------------|\n")
                for d in summary['dismissed']:
                    f.write(
                        f"| #{d['number']} | {d['cve']} | {d['package']} | "
                        f"{d['tuxcare_version']} |\n"
                    )
                f.write("\n")
            
            # Skip reasons
            if summary['skipped_by_reason']:
                f.write("## Skip Reasons\n\n")
                f.write("| Reason | Count |\n")
                f.write("|--------|-------|\n")
                for reason, count in sorted(summary['skipped_by_reason'].items()):
                    f.write(f"| {reason} | {count} |\n")
                f.write("\n")
            
            # Execution time
            if 'execution_time_seconds' in summary:
                duration = format_duration(summary['execution_time_seconds'])
                f.write(f"**Execution time:** {duration}\n")
    
    except Exception as e:
        # Don't fail the action if step summary creation fails
        print(f"Warning: Failed to create step summary: {e}")


def main() -> int:
    """
    Main entry point.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    start_time = time.time()
    
    try:
        # Load configuration
        config = Config()
        
        # Setup logging
        logger = setup_logging(config.verbosity)
        logger.info("TuxCare VEX Auto-Triage starting...")
        
        # Log token info for debugging (without revealing actual token)
        if config.verbosity == "DEBUG":
            token = config.github_token
            if token:
                token_len = len(token)
                token_prefix = token[:4] if len(token) >= 4 else "???"
                logger.debug(f"Token loaded: length={token_len}, prefix={token_prefix}...")
            else:
                logger.error("Token is empty!")
        
        # Initialize GitHub client
        github_client = GitHubClient(config.github_token, config.github_repository)
        
        # Initialize VEX clients for each ecosystem
        vex_clients: dict[str, VexClient] = {}
        for ecosystem in config.ecosystems:
            vex_url = config.get_vex_url(ecosystem)
            vex_clients[ecosystem] = VexClient(ecosystem, vex_url)
        
        # Create triage engine and run
        engine = TriageEngine(config, github_client, vex_clients)
        summary = engine.triage_alerts()
        
        # Add execution time to summary
        end_time = time.time()
        summary['execution_time_seconds'] = end_time - start_time
        
        # Output summary as JSON
        logger.info("\n" + "=" * 60)
        logger.info("JSON OUTPUT")
        logger.info("=" * 60)
        print(json.dumps(summary, indent=2))
        
        # Create GitHub step summary
        create_github_step_summary(summary)
        
        # Exit with success
        logger.info("\nTuxCare VEX Auto-Triage completed successfully!")
        return 0
        
    except ConfigurationError as e:
        logger = setup_logging("INFO")
        logger.error(f"Configuration error: {e}")
        github_error(str(e), "Configuration Error")
        return 1
        
    except KeyboardInterrupt:
        logger = setup_logging("INFO")
        logger.warning("Interrupted by user")
        return 130
        
    except Exception as e:
        logger = setup_logging("INFO")
        logger.error(f"Unexpected error: {e}")
        logger.error(traceback.format_exc())
        github_error(str(e), "Unexpected Error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
