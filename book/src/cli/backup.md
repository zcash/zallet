# The `backup` command

`zallet backup <DESTINATION>` writes a consistent snapshot of the wallet database to a
backup file, using SQLite's [Online Backup API]. Unlike copying the database file by
hand, which can capture a torn, unrestorable state if any journal or WAL sidecar files
exist, the snapshot this command produces is always a complete, self-contained database.

[Online Backup API]: https://www.sqlite.org/backup.html

If `DESTINATION` is an existing directory, the backup is written inside it as
`zallet-wallet-backup-<datetime>.db` (UTC timestamp), so repeated backups into the same
directory accumulate rather than collide. Any other path is used as the backup file's
path directly. An existing file is never overwritten: the file in the way may be your
previous good backup.

The backup is written to a temporary file first and only published after it has passed a
database integrity check and been synced to disk, and publication never replaces an
existing file, even one that appeared while the copy was running. The refusal is atomic
on Windows on every filesystem, and on Linux, Android, and Apple platforms wherever the
filesystem supports no-replace renames (on Linux that includes FAT and exFAT) or hard
links; only when neither is available does it degrade to a checked fallback. If this command reports
success, the file at `DESTINATION` is a complete, verified backup; if it reports failure,
no partial file is left behind. The one exception is a backup interrupted from outside
(a kill signal or power loss), which can leave the in-progress `<DESTINATION>.partial`
file behind; later backups to the same destination refuse to touch it, and the error
says where it is so it can be deleted once no backup is running.

The backup file is created owner-only from the moment it exists, on Unix (mode `0600`)
and on Windows (a protected owner-only ACL); on any other platform it inherits the
destination directory's access control, so write backups into a directory only your
user can read. The published file's directory entry is made crash-durable on Unix (by
syncing the containing directory) and on Windows (a write-through rename); on any other
platform its durability immediately after success is left to the operating system.

The command works whether or not the wallet is running. Backing up a *running* wallet
never mutates it and never blocks its writes for more than one copy step at a time, and
if the wallet writes while the copy is in flight, SQLite restarts the copy, so the
result is always a transaction-consistent snapshot of a state the wallet actually passed
through. Under sustained write load (for example during initial sync) those restarts can
keep the backup from ever completing; rather than run forever, the command fails loudly
after ten minutes, and likewise after thirty seconds of continuous database contention.
If that happens, retry when the wallet is less busy, or stop the wallet and retry.

One caveat for a *stopped* wallet: if it was stopped uncleanly, the database may need
crash recovery, which this command's read-only connection refuses to perform: start and
cleanly stop the wallet once, then back up. (Scheduled periodic backups from inside the
running process are also planned as part of [#195]; this command complements them, and
works even when the wallet process is unresponsive.)

> **Warning**
> The wallet database holds key material in encrypted form only, so this backup is not
> sufficient to restore a wallet by itself: restoring also requires the wallet's age
> encryption identity file. The identity never changes, so back it up once, and store it
> separately from database backups, because anyone holding both can decrypt the wallet's
> key material. See [Backup and restore](../guide/backup.md) for what a complete backup
> requires, and the [threat model](../security/threat-model.md) for why backups should be
> encrypted before being uploaded anywhere.

[#195]: https://github.com/zcash/zallet/issues/195
