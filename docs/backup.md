# Backup Architecture

SyncBox creates periodic sealed snapshots of the database and repository state.

## Targets

Snapshots are written to a target directory or mounted network path (e.g., NFS/SMB share).

```bash
syncboxd backup -target /mnt/backups/syncbox
```

## Restoration

To restore a snapshot:

```bash
syncboxd restore -target /mnt/backups/syncbox -to /var/lib/syncbox
```
