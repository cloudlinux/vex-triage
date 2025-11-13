"""Utility functions for TuxCare VEX Auto-Triage."""

import logging
import sys
import time
from functools import wraps
from typing import Callable, TypeVar, Any


# Custom exceptions
class VexFetchError(Exception):
    """Raised when VEX data cannot be fetched."""
    pass


class GitHubAPIError(Exception):
    """Raised when GitHub API calls fail."""
    pass


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass


# Type variable for decorator
T = TypeVar('T')


def setup_logging(level: str = "INFO") -> logging.Logger:
    """
    Configure Python logging with GitHub Actions-friendly format.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("tuxcare-vex")
    logger.setLevel(getattr(logging, level))
    
    # Remove existing handlers to avoid duplicates
    logger.handlers = []
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level))
    
    # Create formatter
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    
    return logger


def github_annotation(level: str, message: str, title: str = "") -> None:
    """
    Output GitHub Actions annotation.
    
    Args:
        level: Annotation level (error, warning, notice)
        message: Annotation message
        title: Optional title for the annotation
    """
    title_str = f" title={title}" if title else ""
    print(f"::{level}{title_str}::{message}")


def github_error(message: str, title: str = "Error") -> None:
    """Output GitHub Actions error annotation."""
    github_annotation("error", message, title)


def github_warning(message: str, title: str = "Warning") -> None:
    """Output GitHub Actions warning annotation."""
    github_annotation("warning", message, title)


def github_notice(message: str, title: str = "Notice") -> None:
    """Output GitHub Actions notice annotation."""
    github_annotation("notice", message, title)


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to retry a function with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds
        backoff_factor: Multiplier for delay after each retry
        exceptions: Tuple of exception types to catch and retry
    
    Returns:
        Decorated function
    
    Example:
        @retry_with_backoff(max_retries=3, initial_delay=1.0)
        def fetch_data():
            return requests.get(url)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logger = logging.getLogger("tuxcare-vex")
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries} failed: {e}. "
                            f"Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        logger = logging.getLogger("tuxcare-vex")
                        logger.error(
                            f"All {max_retries} attempts failed. Last error: {e}"
                        )
            
            # If we get here, all retries failed
            if last_exception:
                raise last_exception
            
            # This shouldn't happen, but just in case
            raise RuntimeError(f"Function {func.__name__} failed after {max_retries} retries")
        
        return wrapper
    return decorator


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
    
    Returns:
        Formatted string (e.g., "1m 23s" or "45.2s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    
    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60
    return f"{minutes}m {remaining_seconds:.0f}s"

