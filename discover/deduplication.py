"""Deduplication logic for candidate hosts."""
from typing import List
from .models import CandidateHost


def deduplicate_candidates(candidates: List[CandidateHost]) -> List[CandidateHost]:
    """Deduplicate candidates by IP:port, merging data.
    
    Args:
        candidates: List of candidate hosts (may contain duplicates)
        
    Returns:
        List of unique candidates with merged data
    """
    seen = {}
    for candidate in candidates:
        key = candidate.key
        if key in seen:
            seen[key] = seen[key].merge_with(candidate)
        else:
            seen[key] = candidate
    
    return list(seen.values())
