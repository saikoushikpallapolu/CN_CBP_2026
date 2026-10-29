"""Bounded, timestamp-preserving packet activity for visual capture replay."""
import math


def packet_timeline(records, max_bins=512):
    if not records:
        return dict(version=1, start=0., end=0., bins=[])
    start = min(stamp for stamp, size in records)
    end = max(stamp for stamp, size in records)
    if not math.isfinite(start) or not math.isfinite(end):
        raise ValueError("Capture timestamps must be finite")
    groups = {}
    for stamp, size in records:
        index = min(max_bins - 1, int((stamp - start) / max(end - start, 1e-9) * max_bins))
        group = groups.setdefault(index, dict(timestamp=stamp, count=0, bytes=0))
        group["timestamp"] = max(group["timestamp"], stamp)
        group["count"] += 1
        group["bytes"] += size
    return dict(version=1, start=start, end=end, bins=[groups[key] for key in sorted(groups)],
                scope="Recorded packet timestamps; dense intervals grouped into at most 512 visual points")
