"""
Context-Aware Threat Detection
Maintains conversation context to detect information leakage across multiple messages.

Example:
  Message 1: "Tomorrow"       -> LOW risk alone
  Message 2: "0600"           -> LOW risk alone
  Message 3: "Base Alpha"     -> LOW risk alone
  Combined across conversation -> HIGH risk (OPSEC leak pattern)
"""

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# In-memory per-channel context (channel_id -> deque of recent messages)
# TTL: last 30 messages or last 30 minutes per channel
_channel_contexts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))

# OPSEC fragment patterns that are individually low-risk but collectively HIGH
TEMPORAL_FRAGMENTS = [
    r'\b\d{4}\b',            # Military time: 0600, 1400
    r'\btomorrow\b',
    r'\btonight\b',
    r'\bat dawn\b',
    r'\b\d+:\d{2}\b',        # Times like 06:00, 14:30
]

LOCATION_FRAGMENTS = [
    r'\bbase\s+\w+\b',       # Base Alpha, Base Bravo
    r'\bgrid\s+\w+\b',       # Grid reference
    r'\bsector\s+\w+\b',     # Sector 7
    r'\bpoint\s+\w+\b',      # Point Zulu
    r'\bzone\s+\w+\b',       # Zone Red
    r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Named locations in title case
]

INTENT_FRAGMENTS = [
    r'\bextract\b', r'\binfiltrat\b', r'\brendezvous\b',
    r'\bmove\s+out\b', r'\badvance\b', r'\bwithdraw\b',
    r'\bhold\s+position\b', r'\bsecure\s+the\b',
]

QUANTITY_FRAGMENTS = [
    r'\b\d+\s+units\b', r'\b\d+\s+personnel\b',
    r'\b\d+\s+troops\b', r'\bteam\s+of\s+\d+\b',
]

def _score_fragments(text: str, patterns: List[str]) -> int:
    """Count how many fragment patterns match in text."""
    count = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            count += 1
    return count

def add_message_to_context(channel_id: str, text: str, sender_id: int):
    """Add a new message to the channel's rolling context window."""
    _channel_contexts[channel_id].append({
        "text": text,
        "sender_id": sender_id,
        "timestamp": datetime.utcnow(),
        "temporal": _score_fragments(text, TEMPORAL_FRAGMENTS),
        "location": _score_fragments(text, LOCATION_FRAGMENTS),
        "intent": _score_fragments(text, INTENT_FRAGMENTS),
        "quantity": _score_fragments(text, QUANTITY_FRAGMENTS),
    })

def get_context_risk(channel_id: str, current_text: str) -> dict:
    """
    Analyse the cumulative context of recent messages in a channel.
    Returns a risk assessment based on accumulated fragments.
    """
    # Purge stale entries (older than 30 minutes)
    cutoff = datetime.utcnow() - timedelta(minutes=30)
    context = _channel_contexts[channel_id]
    fresh = deque(
        (m for m in context if m["timestamp"] >= cutoff),
        maxlen=30
    )
    _channel_contexts[channel_id] = fresh

    # Aggregate fragment scores across all recent messages
    total_temporal = sum(m["temporal"] for m in fresh)
    total_location = sum(m["location"] for m in fresh)
    total_intent = sum(m["intent"] for m in fresh)
    total_quantity = sum(m["quantity"] for m in fresh)

    # Also score the current message
    total_temporal += _score_fragments(current_text, TEMPORAL_FRAGMENTS)
    total_location += _score_fragments(current_text, LOCATION_FRAGMENTS)
    total_intent += _score_fragments(current_text, INTENT_FRAGMENTS)
    total_quantity += _score_fragments(current_text, QUANTITY_FRAGMENTS)

    # Risk matrix: multiple categories together = HIGH leak risk
    categories_triggered = sum([
        total_temporal > 0,
        total_location > 0,
        total_intent > 0,
        total_quantity > 0,
    ])

    reasons = []
    if total_temporal > 0:
        reasons.append(f"Temporal indicator across {len(fresh)+1} messages (e.g. time/day references)")
    if total_location > 0:
        reasons.append(f"Location indicator detected in conversation context")
    if total_intent > 0:
        reasons.append(f"Movement/operational intent language detected")
    if total_quantity > 0:
        reasons.append(f"Force/unit quantity indicator found")

    # Scoring
    if categories_triggered >= 3:
        context_risk = "HIGH"
        context_score = min(40 + (categories_triggered * 10), 60)
    elif categories_triggered == 2:
        context_risk = "SENSITIVE"
        context_score = 25
    else:
        context_risk = "SAFE"
        context_score = 0

    return {
        "context_risk": context_risk,
        "context_score": context_score,
        "context_reasons": reasons,
        "context_message_count": len(fresh),
        "categories_triggered": categories_triggered,
    }

def clear_channel_context(channel_id: str):
    """Reset conversation context (e.g. after a HIGH risk block)."""
    _channel_contexts[channel_id].clear()
