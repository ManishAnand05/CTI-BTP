from datetime import datetime, timezone

def calculate_decayed_risk(base_score, observed_at_str):
    """
    Applies exponential decay to the risk score based on how old the threat is.
    Half-life is 30 days.
    """
    if not observed_at_str:
        return base_score

    try:
        # Handle SQLite timestamp formats
        observed_at = datetime.fromisoformat(observed_at_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age_in_days = (now - observed_at).days
        
        # Exponential Decay Formula: Score * (0.5 ^ (Age / 30))
        decay_factor = 0.5 ** (max(0, age_in_days) / 30.0)
        decayed_score = base_score * decay_factor
        
        return max(10, round(decayed_score)) # Minimum score is always 10
    except Exception:
        return base_score