#!/usr/bin/env python3
"""Agent Archivist release transactions; every publication is bound to checked evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
import tempfile
import urllib.parse
import urllib.request
import urllib.error

VERSION_FILE = 'containers/agent-archivist/VERSION'
SBOM = 'containers/agent-archivist/sbom.json'
PUBLIC_KEY = 'containers/agent-archivist/release.pub'
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
REPO = 'jedarden/agent-archivist'
IMAGE = 'ronaldraygun/agent-archivist'

def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()

def git(*args):
    return run('git', *args)

def digest(path):
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()

def version():
    value = Path(VERSION_FILE).read_text().strip()
    if not SEMVER.fullmatch(value):
        raise ValueError('VERSION must be strict stable SemVer')
    if tomllib.loads(Path('Cargo.toml').read_text())['workspace']['package']['version'] != value:
        raise ValueError('Cargo workspace and VERSION differ')
    return value

def gate(tag, revision):
    value = version()
    if tag != 'v' + value or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('tag, VERSION and full source revision are required')
    if git('rev-parse', 'HEAD') != revision:
        raise ValueError('checkout differs from source revision')
    git('cat-file', '-e', 'refs/tags/' + tag + '^{tag}')
    if git('rev-parse', 'refs/tags/' + tag + '^{commit}') != revision:
        raise ValueError('annotated tag differs from source revision')
    return value

def verify_published(release, revision, value):
    """A duplicate event is a no-op only after the published bytes verify."""
    if release.get('target_commitish') != revision or release.get('tag_name') != 'v' + value:
        raise ValueError('published release belongs to another source/version')
    assets = api('releases/' + str(release['id']) + '/assets')
    by_name = {a['name']: a for a in assets}
    if len(by_name) != len(assets):
        raise ValueError('ambiguous published assets')
    archives = {f'agent-archivist-{value}-linux-{arch}.tar.gz' for arch in ('amd64', 'arm64')}
    scans = {f'container-scan-{arch}.json' for arch in ('amd64', 'arm64')}
    required = archives | scans | {'release-manifest.json', 'release-manifest.json.bundle', 'verification-manifest.json', 'SHA256SUMS', 'sbom.json'}
    if not required.issubset(by_name):
        raise ValueError('published release is missing required assets')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in sorted(required):
            download_asset(by_name[name]['browser_download_url'], root / name)
        manifest = root / 'release-manifest.json'
        subprocess.run(['cosign', 'verify-blob', '--key', PUBLIC_KEY, '--insecure-ignore-tlog', '--bundle', str(manifest) + '.bundle', str(manifest)], check=True)
        record = json.loads(manifest.read_text())
        if record['commit'] != revision or record['version'] != value or set(record['archives']) != archives or set(record['container_scans']) != scans:
            raise ValueError('signed release record differs from requested source/version')
        for name, expected in {**record['archives'], **record['container_scans'], 'sbom.json': record['sbom_digest']}.items():
            if digest(root / name) != expected:
                raise ValueError('published asset checksum mismatch: ' + name)
        if record['sbom_digest'] != digest(SBOM):
            raise ValueError('published SBOM differs from source')
        verification = root / 'verification-manifest.json'
        if json.loads(verification.read_text()) != record['verification_manifest']:
            raise ValueError('published verification evidence differs from signed manifest')
        subprocess.run(['python3', 'tools/verification-manifest.py', 'check', '--manifest', str(verification)], check=True)
        sums = dict((name.removeprefix('./'), 'sha256:' + sha) for sha, name in (line.split() for line in (root / 'SHA256SUMS').read_text().splitlines()))
        if sums != record['archives']:
            raise ValueError('published checksum list differs from signed manifest')
        image = record['image']
        if not re.fullmatch(re.escape(IMAGE) + r'@sha256:[a-f0-9]{64}', image):
            raise ValueError('invalid signed image reference')
        subprocess.run(['cosign', 'verify', '--key', PUBLIC_KEY, '--insecure-ignore-tlog', image], check=True)
        if json.loads(run('docker', 'buildx', 'imagetools', 'inspect', '--format', '{{json .Manifest.Digest}}', IMAGE + ':' + value)) != image.split('@')[1]:
            raise ValueError('published image tag differs from signed manifest')

def download_asset(url, destination):
    if urllib.parse.urlsplit(url).netloc != 'git.ardenone.com' or not url.startswith('https://'):
        raise ValueError('unexpected asset download origin')
    class SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not newurl.startswith('https://'):
                raise ValueError('insecure asset redirect')
            result = super().redirect_request(req, fp, code, msg, headers, newurl)
            if urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
                result.remove_header('Authorization')
            return result
    request = urllib.request.Request(url, headers={'Authorization': 'token ' + os.environ['FORGEJO_TOKEN']})
    with urllib.request.build_opener(SafeRedirect()).open(request, timeout=120) as response, destination.open('wb') as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)

def release_plan(source, value, tag):
    release = api('releases/tags/' + tag)
    if release and not release['draft']:
        verify_published(release, source, value)
        return {'revision': source, 'version': value, 'tag': tag, 'should_release': 'false'}
    return {'revision': source, 'version': value, 'tag': tag, 'should_release': 'true'}

def prepare(source, tag=''):
    if git('status', '--porcelain', '--untracked-files=no'):
        raise ValueError('release source has tracked changes')
    if git('rev-parse', 'HEAD') != source:
        raise ValueError('source mismatch')
    git('fetch', '--quiet', '--tags', 'origin')
    current = version()
    if tag:
        gate(tag, source)
        return release_plan(source, current, tag)
    tags = [t for t in git('tag', '--list', 'v*').splitlines() if SEMVER.fullmatch(t[1:])]
    numbers = lambda v: tuple(map(int, v.split('.')))
    latest = max((t[1:] for t in tags), key=numbers, default=None)
    at_head = 'v' + current in tags and git('rev-parse', 'v' + current + '^{commit}') == source
    if at_head:
        gate('v' + current, source)
        return release_plan(source, current, 'v' + current)
    if latest and numbers(current) < numbers(latest):
        raise ValueError('source version predates latest release')
    # An explicitly increased version is authoritative. With no tags compare the parent.
    prior = latest
    if prior is None:
        try:
            first = git('log', '--reverse', '--format=%H', '--', VERSION_FILE).splitlines()[0]
            prior = git('show', first + ':' + VERSION_FILE).strip()
        except subprocess.CalledProcessError:
            prior = current
    chosen = current if numbers(current) > numbers(prior) else '.'.join(map(str, (*numbers(current)[:2], numbers(current)[2] + 1)))
    remote = git('ls-remote', 'origin', 'refs/heads/main').split()[0]
    if remote != source:
        raise ValueError('main advanced; verify that source instead')
    paths = []
    if chosen != current:
        root = Path('Cargo.toml')
        text, count = re.subn(r'(?ms)(^\[workspace\.package\]\n(?:(?!^\[).)*?^version\s*=\s*)"' + re.escape(current) + '"', lambda m: m[1] + '"' + chosen + '"', root.read_text(), count=1)
        if count != 1:
            raise ValueError('workspace version is ambiguous')
        root.write_text(text)
        Path(VERSION_FILE).write_text(chosen + '\n')
        lock = Path('Cargo.lock')
        chunks = re.split(r'(?m)(?=^\[\[package\]\]$)', lock.read_text())
        for i, chunk in enumerate(chunks):
            if chunk.startswith('[[package]]'):
                entry = tomllib.loads(chunk)['package'][0]
                if entry.get('source') is None and entry['version'] == current:
                    chunks[i] = chunk.replace('version = "' + current + '"', 'version = "' + chosen + '"', 1)
        lock.write_text(''.join(chunks))
        env = dict(os.environ, SOURCE_DATE_EPOCH=git('show', '-s', '--format=%ct', source))
        subprocess.run(['bash', 'containers/agent-archivist/generate-sbom.sh', '--output', SBOM], env=env, check=True, stdout=subprocess.PIPE)
        paths = ['Cargo.toml', 'Cargo.lock', VERSION_FILE, SBOM]
        git('config', 'user.name', 'jedarden')
        git('config', 'user.email', 'github@jedarden.com')
        git('add', '--', *paths)
        run('git', 'commit', '-m', 'ci: prepare agent-archivist release v' + chosen + '\n\nCI-Release-Source: ' + source, '--', *paths, env=dict(os.environ, GIT_AUTHOR_DATE='@' + env['SOURCE_DATE_EPOCH'], GIT_COMMITTER_DATE='@' + env['SOURCE_DATE_EPOCH']))
        git('push', 'origin', 'HEAD:refs/heads/main')
    return {'revision': git('rev-parse', 'HEAD'), 'version': chosen, 'tag': 'v' + chosen, 'should_release': 'true'}

def evidence(outcomes, output):
    rows = dict(line.rstrip('\n').split('\t', 1) for line in Path(outcomes).read_text().splitlines() if line)
    required = set(re.findall(r'run_check\s+"([^"]+)"', Path('scripts/definition-of-done.sh').read_text()))
    if not required or not required.issubset(rows) or rows.get('cargo test') != 'pass' or any(value != 'pass' for value in rows.values()):
        raise ValueError('full DoD test outcomes are not passing')
    register = json.loads(Path('tools/verification-register.json').read_text())
    for requirement in register['requirements'].values():
        if requirement['status'] != 'implemented':
            continue
        for vid in requirement['verifications']:
            check = register['verifications'][vid]
            # A successful workspace test run covers these mapped Rust test sources.
            # New release/operational requirements must provide their real evidence.
            locator = check.get('locator', '')
            if check['kind'] != 'test' or check['lane'] != 'slow' or not locator.startswith('crates/') or not locator.endswith('.rs'):
                raise ValueError('additional release evidence required for ' + vid)
            if not Path(locator).is_file():
                raise ValueError('mapped test source is absent')
            if re.search(r'#\[ignore|#\[cfg\([^)]*(?:feature|target_)', Path(locator).read_text()):
                raise ValueError('mapped test requires evidence beyond the default workspace test scope')
            rows[vid] = 'pass'
    mapped = Path(output).with_suffix('.outcomes.json')
    mapped.write_text(json.dumps(rows))
    subprocess.run(['python3', 'tools/verification-manifest.py', 'emit', '--outcomes', str(mapped), '--output', output], check=True)
    subprocess.run(['python3', 'tools/verification-manifest.py', 'check', '--manifest', output], check=True)

def tag_release(revision, tag, manifest):
    if git('rev-parse', 'HEAD') != revision or tag != 'v' + version():
        raise ValueError('candidate source/version differs')
    subprocess.run(['python3', 'tools/verification-manifest.py', 'check', '--manifest', manifest], check=True)
    if git('ls-remote', 'origin', 'refs/heads/main').split()[0] != revision:
        raise ValueError('main advanced before release')
    refs = git('ls-remote', 'origin', 'refs/tags/' + tag)
    if refs:
        git('fetch', '--quiet', 'origin', 'refs/tags/' + tag + ':refs/tags/' + tag)
        gate(tag, revision)
        return
    git('config', 'user.name', 'jedarden')
    git('config', 'user.email', 'github@jedarden.com')
    git('tag', '-a', tag, '-m', 'Verified Agent Archivist release ' + tag, revision)
    git('push', 'origin', 'refs/tags/' + tag)

def api(path, method='GET', data=None, content_type='application/json'):
    body = None if data is None else (json.dumps(data).encode() if content_type == 'application/json' else data)
    request = urllib.request.Request('https://git.ardenone.com/api/v1/repos/' + REPO + '/' + path, method=method, data=body, headers={'Authorization': 'token ' + os.environ['FORGEJO_TOKEN'], 'Content-Type': content_type})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if method == 'GET' and exc.code == 404:
            return None
        raise

def publish(revision, tag, image_digest, manifest, archives):
    value = gate(tag, revision)
    release = api('releases/tags/' + tag)
    if release and release.get('target_commitish') != revision:
        raise ValueError('release record belongs to another source')
    if release and not release['draft']:
        raise ValueError('published release is immutable; replay refused')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_digest):
        raise ValueError('invalid image digest')
    subprocess.run(['python3', 'tools/verification-manifest.py', 'check', '--manifest', manifest], check=True)
    if not Path(PUBLIC_KEY).is_file():
        raise ValueError('committed signing public key is absent')
    expected = {f'agent-archivist-{value}-linux-{arch}.tar.gz' for arch in ('amd64', 'arm64')}
    files = {p.name: p for p in Path(archives).glob('*.tar.gz')}
    if set(files) != expected:
        raise ValueError('both exact-version Linux archives are required')
    sums = dict((name.removeprefix('./'), sha) for sha, name in (line.split() for line in (Path(archives) / 'SHA256SUMS').read_text().splitlines()))
    if set(sums) != expected or any(digest(files[name]) != 'sha256:' + sums[name] for name in expected):
        raise ValueError('archive checksum mismatch')
    target = IMAGE + ':' + value
    probe = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', '--format', '{{json .Manifest.Digest}}', target], text=True, capture_output=True)
    if probe.returncode == 0 and json.loads(probe.stdout) != image_digest:
        raise ValueError('immutable version already names another image digest')
    if probe.returncode and not any(term in probe.stderr.lower() for term in ('not found', 'manifest unknown')):
        raise ValueError('cannot establish immutable image tag absence')
    image = IMAGE + '@' + image_digest
    subprocess.run(['cosign', 'sign', '--key', 'env://COSIGN_PRIVATE_KEY', '--use-signing-config=false', '--tlog-upload=false', '--yes', image], check=True)
    subprocess.run(['cosign', 'verify', '--key', PUBLIC_KEY, '--insecure-ignore-tlog', image], check=True)
    scans = {f'container-scan-{arch}.json': Path(archives) / f'container-scan-{arch}.json' for arch in ('amd64', 'arm64')}
    for scan in scans.values():
        report = json.loads(scan.read_text())
        if any(v.get('Severity') in ('HIGH', 'CRITICAL') for result in report.get('Results', []) for v in result.get('Vulnerabilities', [])):
            raise ValueError('container vulnerability gate failed')
        if report.get('ArtifactName') != image:
            raise ValueError('container scan belongs to another image')
    record = {'version': value, 'commit': revision, 'image': image, 'archives': {n: digest(p) for n, p in files.items()}, 'verification_manifest': json.loads(Path(manifest).read_text()), 'sbom_digest': digest(SBOM), 'container_scans': {name: digest(path) for name, path in scans.items()}, 'support_claims': {'backblaze_b2': 'not claimed by this automated release', 'aws_s3': 'unqualified', 'garage': 'unqualified'}}
    record_path = Path(archives) / 'release-manifest.json'; record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    bundle = str(record_path) + '.bundle'
    subprocess.run(['cosign', 'sign-blob', '--key', 'env://COSIGN_PRIVATE_KEY', '--yes', '--use-signing-config=false', '--tlog-upload=false', '--bundle', bundle, str(record_path)], check=True)
    subprocess.run(['cosign', 'verify-blob', '--key', PUBLIC_KEY, '--insecure-ignore-tlog', '--bundle', bundle, str(record_path)], check=True)
    if probe.returncode:
        subprocess.run(['docker', 'buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', target, image], check=True)
    actual = run('docker', 'buildx', 'imagetools', 'inspect', '--format', '{{json .Manifest.Digest}}', target)
    if json.loads(actual) != image_digest:
        raise ValueError('published image tag differs from the signed digest')
    if release is None:
        source = 'https://git.ardenone.com/' + REPO + '/src/commit/' + revision + '/'
        notes = ('Automated preview release. Exact verification and artifact digests are in the signed release manifest.\n\n'
                 'Supported adapters and source fingerprints: ' + source + 'docs/notes/compatibility-matrix.md\n'
                 'Storage claims: isolated MinIO reference only. B2 is not claimed by this automated release; a release-specific live qualification is required. AWS S3 and Garage remain unqualified. Registry: ' + source + 'docs/notes/storage-profiles.md\n'
                 'Coverage gaps and schema versions: ' + source + 'docs/plan/plan.md\n'
                 'Deduplication guarantees: ' + source + 'README.md\n'
                 'No additional provider or production-readiness claims are made by this automation.')
        release = api('releases', 'POST', {'tag_name': tag, 'target_commitish': revision, 'name': 'Agent Archivist ' + tag, 'draft': True, 'prerelease': value.startswith('0.'), 'body': notes})
    assets = api('releases/' + str(release['id']) + '/assets')
    for p in [*files.values(), Path(archives) / 'SHA256SUMS', record_path, Path(bundle), Path(manifest), Path(SBOM), *scans.values()]:
        existing = next((a for a in assets if a['name'] == p.name), None)
        if existing:
            api('releases/' + str(release['id']) + '/assets/' + str(existing['id']), 'DELETE')
        boundary = 'archivist-release-upload'
        body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="attachment"; filename="' + p.name + '"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + p.read_bytes() + ('\r\n--' + boundary + '--\r\n').encode()
        api('releases/' + str(release['id']) + '/assets?name=' + p.name, 'POST', body, 'multipart/form-data; boundary=' + boundary)
    api('releases/' + str(release['id']), 'PATCH', {'draft': False})

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('operation', choices=['prepare', 'gate', 'evidence', 'tag', 'publish']); parser.add_argument('--revision'); parser.add_argument('--tag', default=''); parser.add_argument('--manifest'); parser.add_argument('--outcomes'); parser.add_argument('--output'); parser.add_argument('--digest'); parser.add_argument('--archives')
    args = parser.parse_args()
    if args.operation == 'prepare': print(json.dumps(prepare(args.revision, args.tag)))
    elif args.operation == 'gate': gate(args.tag, args.revision)
    elif args.operation == 'evidence': evidence(args.outcomes, args.output)
    elif args.operation == 'tag': tag_release(args.revision, args.tag, args.manifest)
    else: publish(args.revision, args.tag, args.digest, args.manifest, args.archives)
