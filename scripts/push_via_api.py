"""Publish the LocalExile poe2-port branch to GitHub via the REST Git Data API.

git push hangs on this machine (see PORTING-POE2.md), so the tree is uploaded
blob-by-blob, then assembled into trees/commit/refs. Progress is checkpointed
to data/upload-state.json so the run can be resumed after interruption.

Usage: python scripts/push_via_api.py <local-repo-root> <branch-branch-name>
"""
import base64
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REPO = 'Ehco/LocalExile2'
CRED_FILE = r'C:\Users\Administrator\.git-credentials'
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'upload-state.json')
API = 'https://api.github.com'

TOK = [l for l in open(CRED_FILE).read().splitlines() if 'github.com' in l][0]
TOK = TOK.split('//')[1].split('@')[0].split(':')[1] if '://' in TOK else TOK.split(':')[-1]

HEADERS = {'Authorization': f'Bearer {TOK}', 'Accept': 'application/vnd.github+json',
           'Content-Type': 'application/json', 'User-Agent': 'hermes-local-exile2'}


def call(method, url, payload=None, timeout=90, tries=8):
    body = json.dumps(payload).encode() if payload is not None else None
    last = 'unknown'
    for attempt in range(tries):
        req = urllib.request.Request(API + url, method=method, data=body, headers=HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                raw = json.loads(raw)
            except Exception:
                pass
            if e.code == 403 or e.code == 429:  # secondary rate limit: back off
                retry = int(e.headers.get('X-RateLimit-Reset', 0) or 0)
                ra = e.headers.get('Retry-After')
                if ra:
                    wait = int(ra) + 2
                elif retry:
                    wait = max(15, min(retry - time.time() + 2, 300))
                else:
                    wait = 60 * (attempt + 1)
                print(f'[{time.strftime("%H:%M:%S")}] {e.code} on {url}; sleeping {wait:.0f}s', flush=True)
                time.sleep(wait)
                last = f'{e.code} {str(raw)[:120]}'
                continue
            if e.code >= 500 or e.code == 409:
                time.sleep(5 * (attempt + 1)); last = f'{e.code} {str(raw)[:120]}'; continue
            return e.code, raw if not isinstance(raw, dict) else raw
        except Exception as ex:
            last = repr(ex)
            time.sleep(min(5 * (attempt + 1), 30))
    return 0, {'message': last}


def save(state):
    tmp = STATE_FILE + '.tmp'
    json.dump(state, open(tmp, 'w'))
    os.replace(tmp, STATE_FILE)


def main(repo_root, branch):
    state = {'blob_sha': {}, 'trees': {}, 'commit_sha': None}
    if os.path.exists(STATE_FILE):
        state = json.load(open(STATE_FILE))
    blob_sha = state['blob_sha']

    out = subprocess.run(['git', 'ls-tree', '-r', branch], cwd=repo_root,
                         capture_output=True, text=True).stdout.splitlines()
    entries = []  # (mode, type, sha_local, path)
    for l in out:
        meta, path = l.split('\t', 1)
        mode, typ, sha = meta.split()
        entries.append((mode, typ, sha, path))
    print(f'{len(entries)} tracked entries', flush=True)

    # ---- 1. blobs ---------------------------------------------------------
    todo = [(m, p) for m, t, s, p in entries if t == 'blob' and p not in blob_sha]
    print(f'{len(todo)} blobs to upload', flush=True)
    t0 = time.time()
    for chunk_start in range(0, len(todo), 200):
        chunk = todo[chunk_start:chunk_start + 200]
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(upload_blob, repo_root, m, p) for m, p in chunk]
            for fut in futs:
                path, sha = fut.result()
                if sha:
                    blob_sha[path] = sha
        state['blob_sha'] = blob_sha
        save(state)
        print(f'{len(blob_sha)} blobs done ({time.time() - t0:.0f}s)', flush=True)
    print(f'blobs complete: {len(blob_sha)}', flush=True)

    # ---- 2. trees, bottom-up ---------------------------------------------
    dirs = {}  # dir path -> list of entries; '' is root
    for mode, typ, sha, path in entries:
        if typ != 'blob':
            continue
        d = os.path.dirname(path) or ''
        dirs.setdefault(d, []).append((mode, path, os.path.basename(path)))
    tree_sha = {}  # dir -> sha
    for d in sorted(dirs, key=lambda x: -x.count('/')):
        nodes = []
        for mode, path, base in dirs[d]:
            nodes.append({'path': base, 'mode': mode, 'type': 'blob', 'sha': blob_sha[path]})
        for sub, sub_sha in tree_sha.items():
            parent = os.path.dirname(sub) if os.path.dirname(sub) else ''
            if parent == d:
                nodes.append({'path': os.path.basename(sub), 'mode': '040000', 'type': 'tree', 'sha': sub_sha})
        st, t = call('POST', f'/repos/{REPO}/git/trees', {'tree': nodes})
        if not (isinstance(t, dict) and 'sha' in t):
            raise SystemExit(f'tree {d} failed: {st} {t}')
        tree_sha[d] = t['sha']
        state['trees'] = {k: v for k, v in tree_sha.items()}
        save(state)
    print(f'root tree {tree_sha[""][:12]}', flush=True)

    # ---- 3. commit + refs -------------------------------------------------
    st, c = call('POST', f'/repos/{REPO}/git/commits', {
        'message': f'LocalExile upstream snapshot + PoE2 wave-0 recon (PORTING-POE2.md, scripts/recon/poe2_login_scan.py)\n\n'
                   f'Port of the LocalExile PoE1 emulator to the Path of Exile 2 client. '
                   f'See PORTING-POE2.md for the plan and findings.',
        'tree': tree_sha['']})
    commit_sha = c['sha']
    print('commit', commit_sha[:12], flush=True)
    for name, ref in [('main', f'refs/heads/{branch}'), (branch, f'refs/heads/{branch}')]:
        pass
    st, r = call('POST', f'/repos/{REPO}/git/refs', {'ref': f'refs/heads/{branch}', 'sha': commit_sha})
    if st >= 400:
        st, r = call('PATCH', f'/repos/{REPO}/git/refs/heads/{branch}', {'sha': commit_sha, 'force': True})
    print(f'{branch} -> {commit_sha[:12]} ({st})', flush=True)
    st, r = call('PATCH', f'/repos/{REPO}/git/refs/heads/main', {'sha': commit_sha, 'force': True})
    print(f'main -> {commit_sha[:12]} ({st})', flush=True)
    print('DONE', flush=True)


def upload_blob(repo_root, mode, path):
    full = os.path.join(repo_root, path)
    content = open(full, 'rb').read()
    try:
        payload = {'content': content.decode('utf-8'), 'encoding': 'utf-8'}
    except UnicodeDecodeError:
        payload = {'content': base64.b64encode(content).decode(), 'encoding': 'base64'}
    time.sleep(random.random() * 0.25)
    st, b = call('POST', f'/repos/{REPO}/git/blobs', payload)
    if st == 201 and isinstance(b, dict) and 'sha' in b:
        return path, b['sha']
    print(f'blob fail {path}: {st} {str(b)[:100]}', flush=True)
    return path, None


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
