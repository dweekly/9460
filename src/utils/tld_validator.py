"""TLD validation using IANA's authoritative list."""

import logging
from pathlib import Path
from typing import Optional, Set
from urllib.request import urlopen

logger = logging.getLogger(__name__)

# IANA TLD list URL
IANA_TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# Cache file location
TLD_CACHE_FILE = Path.home() / ".cache" / "rfc9460_checker" / "tlds.txt"

# Global cache for TLDs
_tld_cache: Optional[Set[str]] = None


def fetch_tld_list() -> Set[str]:
    """Fetch the authoritative TLD list from IANA.

    Returns:
        Set of valid TLDs in lowercase.
    """
    try:
        logger.info("Fetching TLD list from IANA")
        with urlopen(IANA_TLD_URL) as response:
            content = response.read().decode("utf-8")

        # Parse TLDs (skip comment lines starting with #)
        tlds = set()
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                tlds.add(line.lower())

        logger.info(f"Fetched {len(tlds)} TLDs from IANA")
        return tlds

    except Exception as e:
        logger.error(f"Failed to fetch TLD list: {e}")
        return set()


def save_tld_cache(tlds: Set[str]) -> None:
    """Save TLD list to cache file.

    Args:
        tlds: Set of TLDs to cache.
    """
    try:
        TLD_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(TLD_CACHE_FILE, "w") as f:
            for tld in sorted(tlds):
                f.write(f"{tld}\n")
        logger.debug(f"Saved TLD cache to {TLD_CACHE_FILE}")
    except Exception as e:
        logger.error(f"Failed to save TLD cache: {e}")


def load_tld_cache() -> Optional[Set[str]]:
    """Load TLD list from cache file.

    Returns:
        Set of TLDs if cache exists and is recent, None otherwise.
    """
    try:
        if not TLD_CACHE_FILE.exists():
            return None

        # Check if cache is less than 7 days old
        import time

        cache_age = time.time() - TLD_CACHE_FILE.stat().st_mtime
        if cache_age > 7 * 24 * 3600:  # 7 days
            logger.info("TLD cache is stale, will refresh")
            return None

        with open(TLD_CACHE_FILE) as f:
            tlds = {line.strip().lower() for line in f if line.strip()}

        logger.debug(f"Loaded {len(tlds)} TLDs from cache")
        return tlds

    except Exception as e:
        logger.error(f"Failed to load TLD cache: {e}")
        return None


def get_valid_tlds() -> Set[str]:
    """Get the set of valid TLDs, using cache if available.

    Returns:
        Set of valid TLDs in lowercase.
    """
    global _tld_cache

    # Return memory cache if available
    if _tld_cache is not None:
        return _tld_cache

    # Try to load from file cache
    tlds = load_tld_cache()

    # Fetch from IANA if no cache
    if tlds is None:
        tlds = fetch_tld_list()
        if tlds:
            save_tld_cache(tlds)

    # Store in memory cache
    _tld_cache = tlds
    return tlds


def is_valid_tld(tld: str) -> bool:
    """Check if a TLD is valid according to IANA.

    Args:
        tld: The TLD to check (without leading dot).

    Returns:
        True if the TLD is in IANA's list, False otherwise.
    """
    valid_tlds = get_valid_tlds()

    # If we couldn't fetch the list, be permissive
    if not valid_tlds:
        logger.warning("No TLD list available, accepting any TLD")
        return True

    return tld.lower() in valid_tlds


def validate_domain_tld(domain: str) -> bool:
    """Validate that a domain uses a real IANA TLD.

    Args:
        domain: The domain name to validate.

    Returns:
        True if the domain's TLD is valid, False otherwise.
    """
    # Remove trailing dot if present
    if domain.endswith("."):
        domain = domain[:-1]

    # Extract TLD (last part after final dot)
    parts = domain.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    return is_valid_tld(tld)


# Pre-populate with common TLDs as fallback
COMMON_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "eu",
    "uk",
    "us",
    "de",
    "fr",
    "jp",
    "cn",
    "au",
    "ca",
    "br",
    "in",
    "ru",
    "info",
    "biz",
    "name",
    "pro",
    "museum",
    "coop",
    "aero",
    "io",
    "ai",
    "app",
    "dev",
    "tech",
    "xyz",
    "online",
    "site",
    "web",
}


def init_tld_cache() -> None:
    """Initialize TLD cache on module load (non-blocking)."""
    import threading

    def _init():
        try:
            get_valid_tlds()
        except Exception:
            pass  # Silently fail, will retry on actual use

    # Start in background thread to avoid blocking
    thread = threading.Thread(target=_init, daemon=True)
    thread.start()
