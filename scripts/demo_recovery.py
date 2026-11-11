import hashlib
from pathlib import Path
from sanctum.dal import VirtualDevice
from sanctum.recovery import (
    DeletedFileReconstructor,
    RecoveryGrade,
)


def main():
    lab_dir = Path("test_lab")
    lab_dir.mkdir(parents=True, exist_ok=True)
    disk_path = lab_dir / "recovery_demo.img"

    # Create 1MB disk
    with open(disk_path, "wb") as f:
        f.seek(1024 * 1024 - 1)
        f.write(b"\x00")

    ground_truth_report = b"CONFIDENTIAL INVESTIGATION NOTES - SUSPECT ADMISSIONS\n" + (b"DATA" * 50)
    expected_hash = hashlib.sha256(ground_truth_report).hexdigest()

    # Write report at cluster 2 (LBA 32)
    with open(disk_path, "r+b") as f:
        f.seek(32 * 512)
        f.write(ground_truth_report)

    print("=" * 65)
    print(" SANCTUM M11 DELETED FILE RECONSTRUCTION DEMO")
    print("=" * 65)
    print(f"Target evidence image: {disk_path}")

    vdev = VirtualDevice(disk_path)
    source_pre_hash = hashlib.sha256(disk_path.read_bytes()).hexdigest()

    # Simulate deleted entry discovery from metadata
    deleted_entries = [
        {
            "name": "CONFESSION.TXT",
            "first_cluster": 2,
            "size": len(ground_truth_report),
            "parent_id": 5,
        },
        {
            "name": "ORPHANED_PHOTO.PNG",
            "first_cluster": 10,
            "size": 512,
            "parent_id": 9999,  # Unresolvable parent -> $OrphanFiles
        },
    ]

    parent_map = {5: "/Suspect_Device/Documents"}

    reconstructor = DeletedFileReconstructor(vdev, case_id="CASE-2026-M11", evidence_id="EVID-007")

    print("\nExecuting deleted file reconstruction with overwrite checking...")
    recovered = reconstructor.reconstruct_from_fat(
        deleted_entries=deleted_entries,
        allocated_clusters=set(),  # All free
        sec_per_cluster=1,
        cluster_heap_start_lba=32,
        parent_paths=parent_map,
    )

    print("-" * 65)
    for rec in recovered:
        print(f"File:           {rec.reconstructed_path}")
        print(f"Grade:          {rec.grade.value}")
        print(f"Size:           {rec.size_bytes} bytes")
        print(f"SHA-256:        {rec.sha256}")
        print(f"Validation:     {'PASSED (' + rec.validator_type + ')' if rec.validation_passed else 'FAILED/PARTIAL'}")
        print(f"Source LBA:     {rec.provenance.source_lba}")
        print(f"Overwritten:    {rec.provenance.overwritten_clusters}")
        print("-" * 65)

    # Compile and seal manifest
    manifest_path = lab_dir / "recovery_manifest.json"
    manifest = reconstructor.create_manifest(recovered)
    manifest.save_to_file(str(manifest_path))

    print(f"Case Manifest Generated: {manifest_path}")
    print(f"Manifest SHA-256 Seal:   {manifest.manifest_sha256}")
    print(f"Total Recovered:         {manifest.total_recovered} (Intact: {manifest.intact_count}, Partial: {manifest.partial_count})")

    # Verify source was never modified
    source_post_hash = hashlib.sha256(disk_path.read_bytes()).hexdigest()
    print(f"Source Unaltered:        {source_pre_hash == source_post_hash}")
    print("=" * 65)

    vdev.close()


if __name__ == "__main__":
    main()
