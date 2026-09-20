#!/usr/bin/env python3
"""Stage an independent directory tree from an immutable published generation.

Unchanged, already-normalized report files share their published inode until
the atomic directory swap. Overlay destinations are omitted completely and
subsequently receive independent copies of analyzer outputs. Never link the
mutable analyzer/source tree; those files can be rewritten in place.
"""

from __future__ import annotations

import errno
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import sys


LINK_FALLBACK_ERRORS = {
    errno.EXDEV, errno.EPERM, errno.EACCES, errno.EMLINK,
    errno.ENOSYS, errno.EOPNOTSUPP,
}


def stage_baseline(source, destination, overlays, uid, gid):
    """Copy directory structure, reusing only immutable, normalized files.

    The caller holds the pipeline lock and owns the empty sibling staging
    directory. Failed staging is discarded by the caller; the live tree is
    never changed. State markers/design imports get independent copies even
    though their current producers also use atomic replacement.
    """
    source, destination = Path(source), Path(destination)
    overlays = tuple(Path(item).as_posix().rstrip('/') for item in overlays)
    if any(not item or item.startswith('/') or '..' in item.split('/')
           for item in overlays):
        raise ValueError('invalid overlay path')
    if source.is_symlink() or not source.is_dir():
        raise ValueError('published baseline must be a real directory')
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ValueError('staging destination must be an empty real directory')
    stats = {'linked_files': 0, 'copied_files': 0, 'reused_bytes': 0,
             'copied_bytes': 0}

    def normalize(path, mode):
        info = path.stat(follow_symlinks=False)
        if (info.st_uid, info.st_gid) != (uid, gid):
            os.chown(path, uid, gid, follow_symlinks=False)
        os.chmod(path, mode)

    def visit(current, target):
        normalize(target, 0o775)
        with os.scandir(current) as entries:
            for entry in entries:
                original = Path(entry.path)
                relative = original.relative_to(source).as_posix()
                if any(relative == item or relative.startswith(item + '/')
                       for item in overlays):
                    continue
                candidate = target / entry.name
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    candidate.mkdir()
                    visit(original, candidate)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f'non-regular published artifact: {relative}')
                private = relative == '.lldpq-stale' or relative.startswith('.analysis-state/')
                mode = 0o640 if private else 0o664
                mutable = private or relative.startswith('active-')
                normalized = ((info.st_uid, info.st_gid) == (uid, gid)
                              and stat.S_IMODE(info.st_mode) == mode)
                if normalized and not mutable:
                    try:
                        os.link(original, candidate, follow_symlinks=False)
                    except OSError as exc:
                        if exc.errno not in LINK_FALLBACK_ERRORS:
                            raise
                    else:
                        stats['linked_files'] += 1
                        stats['reused_bytes'] += info.st_size
                        continue
                shutil.copy2(original, candidate)
                normalize(candidate, mode)
                stats['copied_files'] += 1
                stats['copied_bytes'] += info.st_size

    visit(source, destination)
    return stats


def main():
    source, destination, owner, group, *overlays = sys.argv[1:]
    stats = stage_baseline(source, destination, overlays,
                           pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
    print('Scoped publication staging: ' + json.dumps(stats, sort_keys=True))


if __name__ == '__main__':
    main()
