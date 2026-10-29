"""Versioned response recommendations. No networking or firewall side effects."""
POLICY = "simulated-response-v1"


def response_policy(flow):
    prediction = flow["prediction"]
    if prediction == "unknown":
        return dict(policy=POLICY, monitor="review", simulate="review", rate_limit="review", reason=flow.get("uncertainty_reason") or "Uncertain classification",
                    priority="elevated" if flow.get("behavior", {}).get("anomalous") else "normal", enforcement="simulation_only")
    if prediction == "benign":
        return dict(policy=POLICY, monitor="allow", simulate="allow", rate_limit="allow", reason="Accepted benign prediction", enforcement="simulation_only")
    high = flow["confidence"] >= .75 and flow["entropy"] <= .8
    return dict(policy=POLICY, monitor="alert", simulate="would_block" if high else "alert",
                rate_limit="would_rate_limit" if high else "alert", rate_limit_packets_per_second=5,
                reason="Accepted experimental attack prediction; simulation only, not an approved enforcement policy" if high else "Attack prediction below simulated-block threshold",
                block_ttl_seconds=30, enforcement="simulation_only")
