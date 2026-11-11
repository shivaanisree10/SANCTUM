import random
from typing import List

class VerificationSampler:
    """Determines which LBAs to verify based on statistical and mandatory coverage rules."""
    
    def __init__(self, total_sectors: int, seed: str = None):
        self.total_sectors = total_sectors
        self.rng = random.Random(seed) if seed else random.Random()
        
    def get_mandatory_regions(self) -> List[int]:
        """Returns mandatory LBAs covering the start, middle, and end of the drive."""
        if self.total_sectors == 0:
            return []
        
        # Start region (first 1%)
        start_end = max(1, self.total_sectors // 100)
        # Middle region (middle 1%)
        mid_start = self.total_sectors // 2
        mid_end = min(self.total_sectors, mid_start + start_end)
        # End region (last 1%)
        end_start = max(0, self.total_sectors - start_end)
        
        lbas = set()
        lbas.update(range(0, min(self.total_sectors, start_end)))
        lbas.update(range(mid_start, mid_end))
        lbas.update(range(end_start, self.total_sectors))
        return sorted(list(lbas))
        
    def get_random_sample(self, sample_percentage: float = 5.0) -> List[int]:
        """Returns a seeded random sample of LBAs covering the requested percentage."""
        if self.total_sectors == 0:
            return []
        
        sample_count = int(self.total_sectors * (sample_percentage / 100.0))
        sample_count = max(1, min(sample_count, self.total_sectors))
        
        # We don't sample the entire drive into memory; we generate a sorted sample set
        sampled_lbas = self.rng.sample(range(self.total_sectors), sample_count)
        return sorted(sampled_lbas)

    def get_full_coverage(self) -> range:
        """Returns the full range of LBAs for 100% verification."""
        return range(self.total_sectors)
