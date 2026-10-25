# Backup Architecture

SyncBox creates periodic sealed snapshots of the database and repository state.

## Targets

Snapshots are written to a target directory or mounted network path (e.g., NFS/SMB share).

```bash
syncboxd backup -target /mnt/backups/syncbox
```

## Immutability & WORM Storage

SyncBox supports Write Once, Read Many (WORM) storage configurations to protect backups against accidental deletion, tampering, and ransomware encryption.

- **WORM Storage**: Backups written to dedicated WORM targets (such as hardware-enforced or compliance-configured network shares) are permanently retained until their configured retention window expires.
- **Integrity Verification**: Snapshots are cryptographically signed and sealed with SHA-256 checksums to verify that stored data has not been modified or corrupted.

## Restoration

To restore a snapshot:

```bash
syncboxd restore -target /mnt/backups/syncbox -to /var/lib/syncbox
```
