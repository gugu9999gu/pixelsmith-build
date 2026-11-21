'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash, generateKeyPairSync, randomBytes } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const helper = path.join(__dirname, 'sealed.cjs');
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const archiveScript = `
import io
import sys
import tarfile

filename, member_name, kind = sys.argv[1:]
with tarfile.open(filename, 'w:gz') as archive:
    if kind == 'fixture':
        root = tarfile.TarInfo('.')
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, data in [('./.git/HEAD', b'fixture commit'), ('./src/game.js', b'fixture source')]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o755 if name.endswith('.js') else 0o644
            archive.addfile(member, io.BytesIO(data))
    else:
        member = tarfile.TarInfo(member_name)
        if kind in ('symlink', 'hardlink'):
            member.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
            member.linkname = '../escaped'
        archive.addfile(member, io.BytesIO(b''))
`;

function fixture(t, member = '', kind = 'fixture') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sealed-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const location = name => path.join(directory, name);
  const result = spawnSync('python3', ['-I', '-c', archiveScript, location('archive'), member, kind], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const sourceKey = randomBytes(32).toString('base64');
  const run = (args, key = sourceKey) => spawnSync(process.execPath, [helper, ...args], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, SEALED_SOURCE_KEY: key },
  });
  const plan = (file = 'input', digest = createHash('sha256').update(fs.readFileSync(location(file))).digest('hex')) => {
    const filename = location('plan.json');
    fs.writeFileSync(filename, JSON.stringify({
      commit: '2'.repeat(40),
      payloadUrl: 'https://example.com/input.sealed',
      payloadSha256: digest,
      recipientPublicKey: rsa.publicKey,
    }));
    return filename;
  };
  assert.equal(run(['encrypt-input', location('archive'), location('input')]).status, 0);
  return { location, plan, run, sourceKey };
}

test('source archive round-trips .git and executable file mode', t => {
  const { location, plan, run } = fixture(t);
  const status = run(['decrypt-input', plan(), location('input'), location('result')]);
  assert.equal(status.status, 0, status.stderr);
  assert.equal(status.stdout, '');
  assert.equal(fs.readFileSync(location('result/.git/HEAD'), 'utf8'), 'fixture commit');
  assert.equal(fs.readFileSync(location('result/src/game.js'), 'utf8'), 'fixture source');
  assert.equal(fs.statSync(location('result/src/game.js')).mode & 0o777, 0o700);
});

test('source digest mismatch prevents extraction', t => {
  const { location, plan, run } = fixture(t);
  const status = run(['decrypt-input', plan('input', '0'.repeat(64)), location('input'), location('result')]);
  assert.equal(status.status, 1);
  assert.equal(fs.existsSync(location('result')), false);
});

test('ciphertext tampering is rejected even with an updated digest', t => {
  const { location, plan, run } = fixture(t);
  const payload = fs.readFileSync(location('input'));
  payload[payload.length - 17] ^= 1;
  fs.writeFileSync(location('input'), payload);
  const status = run(['decrypt-input', plan(), location('input'), location('result')]);
  assert.equal(status.status, 1);
  assert.equal(fs.existsSync(location('result')), false);
  assert.equal(fs.readdirSync(path.dirname(location('result'))).some(name => name.startsWith('.sealed-')), false);
});

test('a different source key is rejected without logging either key', t => {
  const { location, plan, run, sourceKey } = fixture(t);
  const wrongKey = randomBytes(32).toString('base64');
  const status = run(['decrypt-input', plan(), location('input'), location('result')], wrongKey);
  assert.equal(status.status, 1);
  assert.equal(fs.existsSync(location('result')), false);
  assert.equal((status.stdout + status.stderr).includes(sourceKey), false);
  assert.equal((status.stdout + status.stderr).includes(wrongKey), false);
});

for (const [name, member, kind] of [
  ['parent traversal', '../escaped', 'file'],
  ['absolute path', '/escaped', 'file'],
  ['interior traversal', 'a/../escaped', 'file'],
  ['symbolic link', 'link', 'symlink'],
  ['hard link', 'link', 'hardlink'],
]) {
  test('authenticated archive rejects ' + name, t => {
    const { location, plan, run } = fixture(t, member, kind);
    const status = run(['decrypt-input', plan(), location('input'), location('result')]);
    assert.equal(status.status, 1);
    assert.equal(fs.existsSync(location('result')), false);
    assert.equal(fs.existsSync(location('escaped')), false);
  });
}

test('output decrypts with the RSA recipient and independently of the source key', t => {
  const { location, plan, run } = fixture(t);
  const config = plan();
  fs.writeFileSync(location('private.pem'), rsa.privateKey, { mode: 0o600 });
  const database = location('result-input');
  assert.equal(run(['encrypt-output', config, location('archive'), database], '').status, 0);
  assert.equal(run(['decrypt-output', config, location('private.pem'), database, location('result')], '').status, 0);
  assert.equal(fs.readFileSync(location('result/src/game.js'), 'utf8'), 'fixture source');

  const tampered = fs.readFileSync(database);
  tampered[tampered.length - 1] ^= 1;
  fs.writeFileSync(database, tampered);
  assert.equal(run(['decrypt-output', config, location('private.pem'), database, location('tampered')], '').status, 1);
  assert.equal(fs.existsSync(location('tampered')), false);
});

test('RSA output encrypted for a different recipient cannot be opened', t => {
  const { location, plan, run } = fixture(t);
  const config = plan();
  const different = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(location('private.pem'), different.privateKey, { mode: 0o600 });
  assert.equal(run(['encrypt-output', config, location('archive'), location('output')], '').status, 0);
  const status = run(['decrypt-output', config, location('private.pem'), location('output'), location('result')], '');
  assert.equal(status.status, 1);
  assert.equal(fs.existsSync(location('result')), false);
});
