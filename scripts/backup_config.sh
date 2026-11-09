#!/usr/bin/env bash
# AutoOps configuration backup: timestamped dir, SHA-256 checksums, metadata, restore notes.
# Never overwrites an existing backup. Does not restore anything automatically.
#
# Usage:
#   backup_config.sh [-d BACKUP_ROOT] [-f FILE_LIST] [-n]     create a backup
#   backup_config.sh verify BACKUP_DIR                         verify checksums of a backup
#   -n  dry run (show what would be backed up)
# Default files: sshd_config, ssh drop-ins, /etc/hosts, /etc/fstab, ufw rules, sudoers.d (readable ones)
set -euo pipefail
umask 077

DEFAULT_FILES=(/etc/ssh/sshd_config /etc/hosts /etc/fstab /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ufw/ufw.conf)
usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

if [[ "${1:-}" == "verify" ]]; then
  dir="${2:-}"; [[ -d "$dir/files" && -f "$dir/SHA256SUMS" ]] || { echo "error: not a backup directory: $dir" >&2; exit 2; }
  (cd "$dir/files" && sha256sum -c ../SHA256SUMS) && echo "OK: all checksums match" || { echo "FAILED: checksum mismatch" >&2; exit 1; }
  exit 0
fi

root=""; list=""; dry=0
while getopts ":d:f:nh" opt; do
  case $opt in
    d) root="$OPTARG" ;; f) list="$OPTARG" ;; n) dry=1 ;; h) usage 0 ;; *) usage 2 ;;
  esac
done
if [[ -z "$root" ]]; then
  if [[ $EUID -eq 0 ]]; then root=/var/backups/autoops; else root="$HOME/autoops-backups"; fi
fi

files=()
if [[ -n "$list" ]]; then
  [[ -f "$list" ]] || { echo "error: file list not found: $list" >&2; exit 2; }
  while IFS= read -r line; do [[ -z "$line" || "$line" == \#* ]] || files+=("$line"); done < "$list"
else
  files=("${DEFAULT_FILES[@]}")
fi
for f in "${files[@]}"; do
  [[ "$f" == /* && "$f" != *..* ]] || { echo "error: only absolute paths without '..' allowed: $f" >&2; exit 2; }
done

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="$root/${stamp}-$(hostname -s)"
if [[ $dry -eq 1 ]]; then
  echo "DRY RUN: would create $dest"
  for f in "${files[@]}"; do [[ -r "$f" && -f "$f" ]] && echo "  would back up $f" || echo "  would skip   $f (missing/unreadable)"; done
  exit 0
fi

mkdir -p "$root"
mkdir "$dest" || { echo "error: backup directory already exists: $dest (refusing to overwrite)" >&2; exit 1; }
mkdir "$dest/files"
copied=0; skipped=0
{
  echo "autoops_backup_version=1"
  echo "created_utc=$stamp"
  echo "hostname=$(hostname)"
  echo "created_by=$(id -un)"
  echo "files:"
} > "$dest/metadata.txt"
for f in "${files[@]}"; do
  if [[ -f "$f" && -r "$f" ]]; then
    cp --parents -p -- "$f" "$dest/files/"
    echo "  - path=$f mode=$(stat -c '%a' -- "$f") owner=$(stat -c '%U:%G' -- "$f") size=$(stat -c '%s' -- "$f")" >> "$dest/metadata.txt"
    copied=$((copied+1))
  else
    echo "  - path=$f SKIPPED (missing or unreadable)" >> "$dest/metadata.txt"
    echo "skip: $f" >&2; skipped=$((skipped+1))
  fi
done
[[ $copied -gt 0 ]] || { echo "error: nothing was backed up; removing empty backup $dest" >&2; rm -r -- "$dest"; exit 1; }
(cd "$dest/files" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$dest/SHA256SUMS"
cat > "$dest/RESTORE.txt" <<RESTORE
Manual restore (nothing is restored automatically):
 1. Verify:  $0 verify "$dest"
 2. Review the file you want back:  diff "$dest/files/<path>" "/<path>"
 3. Copy it, keeping the original permissions, as root:  sudo cp -p "$dest/files/<path>" "/<path>"
 4. For SSH: run 'sudo sshd -t' BEFORE 'sudo systemctl reload ssh'. Keep your current session open.
 5. For UFW: 'sudo ufw reload'. Keep your current session open.
Original owner/mode of each file is recorded in metadata.txt.
RESTORE
echo "Backup created: $dest ($copied file(s) backed up, $skipped skipped)"
