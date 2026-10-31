"""Rebuild the Ehco/LocalExile2 commit with the full directory tree.

Fixes the wave-0 publisher bug: directories containing only subdirectories
(e.g. src/) never got tree nodes, so the first commit only carried root-level
files. All 1242 blobs are already uploaded; this recreates the trees bottom-up
over every directory, then a new commit on top of the previous head, and
repoints main + poe2-port.

Usage: python scripts/fix_tree.py <local-repo-root> <parent-commit-sha>
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from push_via_api import call, save, STATE_FILE

REPO = 'Ehco/LocalExile2'


def main(repo_root, branch, parent):
    state = json.load(open(STATE_FILE))
    blob_sha = state['blob_sha']
    print('blobs available:', len(blob_sha))

    out = subprocess.run(['git', 'ls-tree', '-r', branch], cwd=repo_root,
                         capture_output=True, text=True).stdout.splitlines()
    all_dirs = set()
    entries = []
    for l in out:
        meta, path = l.split('\t', 1)
        mode, typ, sha = meta.split()
        if typ != 'blob':
            continue
        entries.append((mode, path))
        d = os.path.dirname(path) or ''
        all_dirs.add(d)
        # every ancestor directory too
        parts = d.split('/') if d else []
        for i in range(len(parts)):
            all_dirs.add('/'.join(parts[:i]))
    print(f'{len(entries)} blobs across {len(all_dirs)} directories')

    files_by_dir = {}
    for mode, path in entries:
        d = os.path.dirname(path) or ''
        files_by_dir.setdefault(d, []).append((mode, os.path.basename(path), path))

    tree_sha = {}
    for d in sorted(all_dirs, key=lambda x: (-x.count('/'), x == '')):
        # deepest first; the empty root dir is deferred to the very end so all
        # top-level subtrees exist when it is assembled
        nodes = [{'path': base, 'mode': mode, 'type': 'blob', 'sha': blob_sha[path]}
                 for mode, base, path in files_by_dir.get(d, [])]
        for sub, sub_sha in tree_sha.items():
            parent_dir = sub.rsplit('/', 1)[0] if '/' in sub else ''
            if parent_dir == d:
                nodes.append({'path': sub.rsplit('/', 1)[1] if '/' in sub else sub,
                              'mode': '040000', 'type': 'tree', 'sha': sub_sha})
        st, t = call('POST', f'/repos/{REPO}/git/trees', {'tree': nodes})
        if not (isinstance(t, dict) and 'sha' in t):
            raise SystemExit(f'tree {d or "<root>"} failed: {st} {str(t)[:200]}')
        tree_sha[d] = t['sha']
    print(f'root tree {tree_sha[""][:12]} ({len(tree_sha)} trees)', flush=True)

    st, c = call('POST', f'/repos/{REPO}/git/commits', {
        'message': 'Fix tree: include all subdirectory trees (publisher bug)\n\n'
                   'Also updates PORTING-POE2.md: DH groups found intact as CryptoPP\n'
                   'hex-string literals; server static public located at SPKI-0x180.',
        'tree': tree_sha[''], 'parents': [parent]})
    commit = c['sha']
    print('commit', commit[:12], flush=True)
    for ref in ('main', branch):
        st, r = call('PATCH', f'/repos/{REPO}/git/refs/heads/{ref}',
                     {'sha': commit, 'force': True})
        print(f'{ref} -> {commit[:12]} ({st})', flush=True)
    print('DONE', flush=True)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
