#!/usr/bin/env python3
"""Synthetic Git and publication fixtures for the release transaction."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('release_policy', Path(__file__).with_name('release-policy.py'))
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(['git', 'init', '-q', '--bare', str(self.root / 'origin')], check=True)
        (self.root / 'repo').mkdir()
        os.chdir(self.root / 'repo')
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Synthetic Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('remote', 'add', 'origin', str(self.root / 'origin'))
        Path('containers/agent-archivist').mkdir(parents=True)
        Path('scripts').mkdir(); Path('tools').mkdir()
        self.set_version('0.1.0')
        Path(policy.SBOM).write_text('{}\n')
        Path(policy.PUBLIC_KEY).write_text('synthetic public-key fixture\n')
        Path('containers/agent-archivist/generate-sbom.sh').write_text('printf "{}\\n" > containers/agent-archivist/sbom.json\n')
        Path('tools/verification-manifest.py').write_text('import sys\nsys.exit(0)\n')
        Path('scripts/definition-of-done.sh').write_text('run_check "cargo test" cargo test --workspace\nrun_check "cargo audit" cargo audit\n')
        self.commit('initial')
        self.git('tag', '-a', 'v0.1.0', '-m', 'initial')
        self.git('push', '-q', 'origin', 'main', '--tags')
        Path('change').write_text('source change\n')
        self.commit('source')
        self.git('push', '-q', 'origin', 'main')
        self.source = self.git('rev-parse', 'HEAD')

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', *args], text=True, stderr=subprocess.PIPE).strip()

    def commit(self, message):
        self.git('add', 'Cargo.toml', 'Cargo.lock', 'containers', 'scripts', 'tools', *(['change'] if Path('change').exists() else []))
        self.git('commit', '-qm', message)

    def set_version(self, value):
        Path('Cargo.toml').write_text('[workspace.package]\nversion = "' + value + '"\n')
        Path(policy.VERSION_FILE).write_text(value + '\n')
        Path('Cargo.lock').write_text('version = 3\n\n[[package]]\nname = "fixture"\nversion = "' + value + '"\n\n[[package]]\nname = "external"\nversion = "0.1.0"\nsource = "registry+https://example.invalid"\n')

    def test_patch_is_atomic_version_commit_without_tag(self):
        result = policy.prepare(self.source)
        self.assertEqual(result['version'], '0.1.1')
        self.assertEqual(policy.version(), '0.1.1')
        self.assertNotEqual(result['revision'], self.source)
        self.assertNotIn('v0.1.1', self.git('tag'))
        self.assertIn('version = "0.1.0"\nsource', Path('Cargo.lock').read_text())
        self.assertEqual(self.git('ls-remote', 'origin', 'refs/heads/main').split()[0], result['revision'])
        self.assertIn('CI-Release-Source: ' + self.source, self.git('show', '-s', '--format=%B'))

    def test_reserved_candidate_retry_reuses_version_with_and_without_tags(self):
        first = policy.prepare(self.source)
        self.assertEqual(policy.prepare(first['revision']), first)
        self.git('push', '-q', 'origin', ':refs/tags/v0.1.0')
        self.git('tag', '-d', 'v0.1.0')
        self.assertEqual(policy.prepare(first['revision']), first)

    def test_new_source_after_failed_candidate_reuses_reserved_version(self):
        first = policy.prepare(self.source)
        Path('change').write_text('fix the failed candidate')
        self.commit('candidate fix'); self.git('push', '-q', 'origin', 'HEAD:main')
        result = policy.prepare(self.git('rev-parse', 'HEAD'))
        self.assertEqual(result['version'], first['version'])
        self.assertNotEqual(result['revision'], first['revision'])
        self.git('push', '-q', 'origin', ':refs/tags/v0.1.0')
        self.git('tag', '-d', 'v0.1.0')
        self.assertEqual(policy.prepare(result['revision'])['version'], first['version'])

    def test_cli_plan_is_json_despite_sbom_diagnostics(self):
        Path('containers/agent-archivist/generate-sbom.sh').write_text('echo "generate-sbom: wrote fixture"\nprintf "{}\\n" > containers/agent-archivist/sbom.json\n')
        self.commit('noisy generator'); self.git('push', '-q', 'origin', 'main')
        source = self.git('rev-parse', 'HEAD')
        result = subprocess.check_output(['python3', str(Path(self.old) / 'scripts/release-policy.py'), 'prepare', '--revision', source], text=True)
        self.assertEqual(json.loads(result)['version'], '0.1.1')

    def test_matching_published_event_is_noop_only_after_verification(self):
        with patch.object(policy, 'api', return_value={'draft': False}), patch.object(policy, 'verify_published') as verify:
            self.assertEqual(policy.release_plan(self.source, '0.1.0', 'v0.1.0')['should_release'], 'false')
            verify.assert_called_once()
        with patch.object(policy, 'api', return_value={'draft': False}), patch.object(policy, 'verify_published', side_effect=ValueError('corrupt asset')):
            with self.assertRaisesRegex(ValueError, 'corrupt asset'):
                policy.release_plan(self.source, '0.1.0', 'v0.1.0')

    def test_explicit_version_is_preserved(self):
        self.set_version('0.2.0'); self.commit('explicit minor')
        self.git('push', '-q', 'origin', 'main')
        source = self.git('rev-parse', 'HEAD')
        self.assertEqual(policy.prepare(source), {'revision': source, 'version': '0.2.0', 'tag': 'v0.2.0', 'should_release': 'true'})

    def test_stale_source_cannot_replace_new_main(self):
        Path('change').write_text('new source'); self.commit('new source')
        self.git('push', '-q', 'origin', 'main')
        self.git('checkout', '--detach', self.source)
        with self.assertRaisesRegex(ValueError, 'main advanced'):
            policy.prepare(self.source)

    def test_annotated_tag_must_match_version_and_source(self):
        self.git('tag', 'v0.1.1')
        with self.assertRaises(ValueError): policy.gate('v0.1.1', self.source)
        with self.assertRaises(ValueError): policy.gate('main', self.source)
        with self.assertRaises(ValueError): policy.gate('v0.1.0', self.source)
        self.git('tag', '-d', 'v0.1.0')
        self.git('tag', 'v0.1.0')
        with self.assertRaises(subprocess.CalledProcessError): policy.gate('v0.1.0', self.source)
        self.git('tag', '-d', 'v0.1.0')
        self.git('tag', '-a', 'v0.1.0', '-m', 'valid')
        self.assertEqual(policy.gate('v0.1.0', self.source), '0.1.0')

    def test_failed_evidence_prevents_tag(self):
        Path('tools/verification-manifest.py').write_text('import sys\nsys.exit(1)\n')
        with self.assertRaises(subprocess.CalledProcessError):
            policy.tag_release(self.source, 'v0.1.0', '/synthetic/manifest')
        self.assertNotEqual(self.git('rev-parse', 'refs/tags/v0.1.0^{commit}'), self.source)

    def test_partial_test_outcomes_are_not_release_evidence(self):
        Path('outcomes.tsv').write_text('cargo test\tpass\n')
        with self.assertRaisesRegex(ValueError, 'full DoD'):
            policy.evidence('outcomes.tsv', 'manifest.json')

    def test_ignored_or_operational_checks_need_separate_evidence(self):
        Path('outcomes.tsv').write_text('cargo test\tpass\ncargo audit\tpass\n')
        Path('crates').mkdir(); Path('crates/tests.rs').write_text('#[ignore]\nfn deferred_test() {}\n')
        record = {'requirements': {'R': {'status': 'implemented', 'verifications': ['T']}}, 'verifications': {'T': {'kind': 'test', 'lane': 'slow', 'locator': 'crates/tests.rs'}}}
        Path('tools/verification-register.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'default workspace'):
            policy.evidence('outcomes.tsv', 'manifest.json')
        record['verifications']['T']['kind'] = 'operational'
        Path('tools/verification-register.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'additional release evidence'):
            policy.evidence('outcomes.tsv', 'manifest.json')

    def test_published_release_replay_is_refused_before_signing(self):
        with patch.object(policy, 'gate', return_value='0.1.0'), patch.object(policy, 'api', return_value={'target_commitish': self.source, 'draft': False}), patch.object(policy.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'immutable'):
                policy.publish(self.source, 'v0.1.0', 'sha256:' + 'a'*64, 'missing', 'missing')
            run.assert_not_called()

    def publication_fixture(self):
        dist = Path('dist'); dist.mkdir()
        for arch in ('amd64', 'arm64'):
            (dist / ('agent-archivist-0.1.0-linux-' + arch + '.tar.gz')).write_bytes(b'synthetic binary archive ' + arch.encode())
        (dist / 'SHA256SUMS').write_text(''.join(policy.digest(p)[7:] + '  ./' + p.name + '\n' for p in dist.glob('*.gz')))
        Path('manifest.json').write_text(json.dumps({'commit': self.source}))
        return dist

    def test_changed_archive_blocks_signing_and_promotion(self):
        dist = self.publication_fixture()
        (dist / 'agent-archivist-0.1.0-linux-amd64.tar.gz').write_bytes(b'corrupted')
        with patch.object(policy, 'gate', return_value='0.1.0'), patch.object(policy, 'api', return_value=None), patch.object(policy.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                policy.publish(self.source, 'v0.1.0', 'sha256:'+'a'*64, 'manifest.json', str(dist))
            self.assertTrue(all(call.args[0][0] == 'python3' for call in run.call_args_list))

    def test_signature_failure_cannot_promote_tag_or_release(self):
        dist = self.publication_fixture(); calls=[]
        def fake_run(command, **kwargs):
            calls.append(command)
            if command[:2] == ['cosign', 'verify']: raise subprocess.CalledProcessError(1, command)
            if command[0] == 'docker': return subprocess.CompletedProcess(command, 1, '', 'manifest unknown')
            return subprocess.CompletedProcess(command, 0)
        with patch.object(policy, 'gate', return_value='0.1.0'), patch.object(policy, 'api', return_value=None) as api, patch.object(policy.subprocess, 'run', side_effect=fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                policy.publish(self.source, 'v0.1.0', 'sha256:'+'a'*64, 'manifest.json', str(dist))
            self.assertFalse(any('create' in call for call in calls))
            self.assertEqual(api.call_count, 1)

    def test_published_noop_rechecks_actual_assets(self):
        dist = self.publication_fixture()
        image = policy.IMAGE + '@sha256:' + 'a'*64
        for arch in ('amd64', 'arm64'):
            (dist / ('container-scan-' + arch + '.json')).write_text(json.dumps({'ArtifactName': image, 'Results': []}))
        shutil.copy('manifest.json', dist / 'verification-manifest.json')
        shutil.copy(policy.SBOM, dist / 'sbom.json')
        record = {'version': '0.1.0', 'commit': self.source, 'image': image,
                  'archives': {p.name: policy.digest(p) for p in dist.glob('*.tar.gz')},
                  'container_scans': {p.name: policy.digest(p) for p in dist.glob('container-scan*.json')},
                  'sbom_digest': policy.digest(policy.SBOM), 'verification_manifest': json.loads(Path('manifest.json').read_text())}
        (dist / 'release-manifest.json').write_text(json.dumps(record))
        (dist / 'release-manifest.json.bundle').write_text('synthetic signature fixture')
        assets = [{'name': p.name, 'browser_download_url': str(p)} for p in dist.iterdir()]
        release = {'target_commitish': self.source, 'tag_name': 'v0.1.0', 'id': 7, 'draft': False}
        with patch.object(policy, 'api', return_value=assets), patch.object(policy, 'download_asset', side_effect=lambda u,p: shutil.copy(u,p)), patch.object(policy.subprocess, 'run') as command, patch.object(policy, 'run', return_value=json.dumps('sha256:'+'a'*64)):
            policy.verify_published(release, self.source, '0.1.0')
            self.assertTrue(any(c.args[0][:2] == ['cosign', 'verify-blob'] for c in command.call_args_list))
            self.assertTrue(any(c.args[0][:2] == ['cosign', 'verify'] for c in command.call_args_list))
            (dist / 'agent-archivist-0.1.0-linux-amd64.tar.gz').write_bytes(b'corrupt existing publication')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                policy.verify_published(release, self.source, '0.1.0')
        with patch.object(policy, 'api', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'missing required assets'):
                policy.verify_published(release, self.source, '0.1.0')

    def test_draft_publishes_last_after_all_signatures_and_assets(self):
        dist = self.publication_fixture(); calls=[]
        image = policy.IMAGE + '@sha256:' + 'a'*64
        for arch in ('amd64', 'arm64'):
            (dist / ('container-scan-' + arch + '.json')).write_text(json.dumps({'ArtifactName': image, 'Results': []}))
        def command(args, **kwargs):
            calls.append(args[:])
            if args[0] == 'docker' and 'inspect' in args: return subprocess.CompletedProcess(args,1,'','manifest unknown')
            if args[:2] == ['cosign','sign-blob']: Path(args[args.index('--bundle')+1]).write_text('synthetic signature fixture')
            return subprocess.CompletedProcess(args,0)
        def request(path, method='GET', *args):
            calls.append(['API',method,path])
            if path.startswith('releases/tags/'):return None
            if path=='releases':return {'id':7,'draft':True,'target_commitish':self.source}
            if path.endswith('/assets') and method=='GET':return []
            return {}
        with patch.object(policy, 'gate', return_value='0.1.0'), patch.object(policy,'api',side_effect=request), patch.object(policy.subprocess,'run',side_effect=command), patch.object(policy,'run',return_value=json.dumps('sha256:'+'a'*64)):
            policy.publish(self.source,'v0.1.0','sha256:'+'a'*64,'manifest.json',str(dist))
        self.assertEqual(calls[-1],['API','PATCH','releases/7'])
        sign_verify = next(i for i,c in enumerate(calls) if c[:2]==['cosign','verify-blob'])
        promote = next(i for i,c in enumerate(calls) if c[:4]==['docker','buildx','imagetools','create'])
        self.assertLess(sign_verify,promote)
        self.assertEqual(len([c for c in calls if c[:2]==['API','POST'] and '/assets?' in c[2]]), 9)

if __name__ == '__main__':
    unittest.main()
