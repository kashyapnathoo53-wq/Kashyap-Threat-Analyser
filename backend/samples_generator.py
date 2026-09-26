from typing import Dict, List, Any, Optional

# Preset sample files removed per user requirement
PRESET_SAMPLES: List[Dict[str, Any]] = []

def get_preset_samples() -> List[Dict[str, Any]]:
    return []

def get_preset_sample_by_id(sample_id: str) -> Optional[Dict[str, Any]]:
    for s in PRESET_SAMPLES:
        if s.get("id") == sample_id:
            return s
    return None
