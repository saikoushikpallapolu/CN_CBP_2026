"""Artifact paths that keep engine metadata separate from training reports."""
from pathlib import Path


def engine_metadata_path(engine):
    path = Path(engine)
    return path.with_name(path.name + ".json")
