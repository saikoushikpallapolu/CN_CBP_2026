"""Compatibility entry point for the bounded, format-aware acquisition tool."""
from scripts.acquire_production_data import main

if __name__ == "__main__":
    import sys
    sys.argv[1:] = ["--sources", "tuesday", *sys.argv[1:]]
    main()
