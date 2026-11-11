import logging
from typing import List, Optional
from sanctum.dal import BaseDevice
from sanctum.partitions.models import (
    PartitionScheme,
    PartitionEntry,
    PartitionMap,
)
from sanctum.partitions.mbr import parse_mbr
from sanctum.partitions.gpt import parse_gpt
from sanctum.partitions.reconstruction import (
    virtually_reconstruct_partitions,
    generate_repair_script,
)
from sanctum.partitions.volume import VirtualVolume

logger = logging.getLogger("sanctum.partitions.mapper")


class PartitionMapper:
    """
    Forensic Volume and Partition Mapper.
    Examines storage devices, extracts partition topologies, validates integrity,
    detects overlaps/anomalies, and provides a virtual read-only volume layer.
    """

    def __init__(self, device: BaseDevice):
        self.device = device
        self._partition_map: Optional[PartitionMap] = None

    def map_partitions(self) -> PartitionMap:
        """
        Parses and evaluates the disk partition topology.
        Attempts GPT -> MBR -> Virtual Reconstruction.
        """
        total_lbas = self.device.info.lba_count
        sector_size = self.device.info.sector_size

        warnings: List[str] = []
        errors: List[str] = []
        repair_notes: List[str] = []
        is_repaired = False
        partitions: List[PartitionEntry] = []
        scheme = PartitionScheme.UNKNOWN

        # 1. Attempt GPT Detection & Parsing (including Backup GPT recovery)
        is_gpt, gpt_parts, gpt_notes, used_backup, gpt_repairs = parse_gpt(self.device)
        warnings.extend(gpt_notes)
        repair_notes.extend(gpt_repairs)

        if is_gpt:
            scheme = PartitionScheme.GPT
            partitions = gpt_parts
            if used_backup:
                is_repaired = True
        else:
            # 2. Attempt MBR Detection & Extended EBR parsing
            is_mbr, mbr_parts, mbr_notes = parse_mbr(self.device)
            warnings.extend(mbr_notes)

            if is_mbr and mbr_parts:
                scheme = PartitionScheme.MBR
                partitions = mbr_parts
            else:
                # 3. Virtual Reconstruction via Signature-based Partition Inference
                logger.info(
                    "Standard partition tables corrupt or missing. "
                    "Triggering virtual reconstruction..."
                )
                inferred_parts, rec_notes = virtually_reconstruct_partitions(self.device)
                repair_notes.extend(rec_notes)

                if inferred_parts:
                    scheme = PartitionScheme.INFERRED
                    partitions = inferred_parts
                    is_repaired = True
                else:
                    scheme = PartitionScheme.UNKNOWN
                    errors.append("No valid or reconstructible partitions discovered on device.")

        # 4. Check Capacity Consistency
        capacity_violations: List[str] = []
        for p in partitions:
            if p.start_lba < 0 or p.end_lba >= total_lbas or p.start_lba > p.end_lba:
                err_msg = (
                    f"Partition {p.index} [{p.start_lba}..{p.end_lba}] exceeds "
                    f"disk boundary [0..{total_lbas - 1}]."
                )
                capacity_violations.append(err_msg)
                errors.append(err_msg)
                p.is_valid = False

        # 5. Detect Overlapping Partitions
        overlaps: List[str] = []
        # Filter out container partitions (like extended MBR) for overlap check
        data_parts = [p for p in partitions if not p.is_extended and p.is_valid]
        sorted_parts = sorted(data_parts, key=lambda x: x.start_lba)

        for i in range(len(sorted_parts) - 1):
            curr_p = sorted_parts[i]
            next_p = sorted_parts[i + 1]
            if curr_p.end_lba >= next_p.start_lba:
                overlap_msg = (
                    f"Overlapping partitions detected: "
                    f"Partition {curr_p.index} [{curr_p.start_lba}..{curr_p.end_lba}] conflicts with "
                    f"Partition {next_p.index} [{next_p.start_lba}..{next_p.end_lba}]."
                )
                overlaps.append(overlap_msg)
                errors.append(overlap_msg)

        is_consistent = (len(capacity_violations) == 0 and len(overlaps) == 0)

        self._partition_map = PartitionMap(
            scheme=scheme,
            total_disk_lbas=total_lbas,
            sector_size=sector_size,
            partitions=partitions,
            is_consistent=is_consistent,
            overlaps=overlaps,
            capacity_violations=capacity_violations,
            warnings=warnings,
            errors=errors,
            is_repaired=is_repaired,
            repair_notes=repair_notes,
        )

        return self._partition_map

    def get_volumes(self) -> List[VirtualVolume]:
        """
        Exposes discovered partitions as virtual read-only volume abstractions.
        """
        if self._partition_map is None:
            self.map_partitions()

        volumes: List[VirtualVolume] = []
        for p in self._partition_map.partitions:
            if not p.is_extended and p.is_valid:
                volumes.append(VirtualVolume(self.device, p))

        return volumes

    def generate_repair_script(self, output_path: str) -> None:
        """
        Generates an external script for offline recovery.
        Does NOT alter the underlying evidence.
        """
        if self._partition_map is None:
            self.map_partitions()

        generate_repair_script(self._partition_map, output_path)
