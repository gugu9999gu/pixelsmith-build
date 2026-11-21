'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { spawnSync } = require('node:child_process');

const INPUT_MAGIC = Buffer.from('PSIN0001');
const OUTPUT_MAGIC = Buffer.from('PSOUT001');
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const SHA256 = /^[a-f0-9]{64}$/;
const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };

function readPlan(filename) {
  const plan = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (!/^[a-f0-9]{40}$/.test(plan.commit) || !SHA256.test(plan.payloadSha256)) {
    throw new Error('Invalid source plan digest or commit');
  }
  const url = new URL(plan.payloadUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new Error('Invalid source plan URL');
  }
  return plan;
}

function sourceKey() {
  const encoded = process.env.SEALED_SOURCE_KEY ?? '';
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32 || key.toString('base64') !== encoded) {
    throw new Error('SEALED_SOURCE_KEY must be canonical base64 for 32 bytes');
  }
  return key;
}

function recipientKey(pem, readKey) {
  const key = readKey(pem);
  const modulusLength = key.asymmetricKeyDetails?.modulusLength;
  if (key.asymmetricKeyType !== 'rsa' || modulusLength < 2048 || modulusLength > 4096) {
    throw new Error('Recipient must use a 2048–4096 bit RSA key');
  }
  return key;
}

async function sha256(filename) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(filename)) {
    hash.update(chunk);
  }
  return hash.digest('hex');
}

async function writeAtomically(output, writer) {
  const directory = await fsp.mkdtemp(path.join(path.dirname(path.resolve(output)), '.sealed-'));
  const temporary = path.join(directory, 'payload');
  try {
    await writer(temporary);
    await fsp.link(temporary, output);
  } finally {
    await fsp.rm(directory, { recursive: true, force: true });
  }
}

async function encrypt(source, output, key, magic, wrappedKey = Buffer.alloc(0)) {
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const length = Buffer.alloc(2);
  length.writeUInt16BE(wrappedKey.length);
  const header = Buffer.concat([magic, nonce, length, wrappedKey]);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(header);
  await writeAtomically(output, async temporary => {
    await fsp.writeFile(temporary, header, { flag: 'wx', mode: 0o600 });
    await pipeline(fs.createReadStream(source), cipher, fs.createWriteStream(temporary, { flags: 'a' }));
    await fsp.appendFile(temporary, cipher.getAuthTag());
  });
}

async function decrypt(source, output, magic, keyForHeader) {
  const input = await fsp.open(source, 'r');
  try {
    async function readAt(length, offset) {
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await input.read(buffer, 0, length, offset);
      if (bytesRead !== length) throw new Error('Truncated envelope');
      return buffer;
    }
    const fixedLength = magic.length + NONCE_BYTES + 2;
    const fixed = await readAt(fixedLength, 0);
    if (!fixed.subarray(0, magic.length).equals(magic)) {
      throw new Error('Unexpected envelope type');
    }
    const wrappedLength = fixed.readUInt16BE(fixedLength - 2);
    if (wrappedLength > 512) throw new Error('Invalid wrapped key length');
    const wrappedKey = await readAt(wrappedLength, fixedLength);
    const header = Buffer.concat([fixed, wrappedKey]);
    const nonce = fixed.subarray(magic.length, magic.length + NONCE_BYTES);
    const { size } = await input.stat();
    if (size <= header.length + TAG_BYTES) throw new Error('Envelope has no ciphertext');
    const tag = await readAt(TAG_BYTES, size - TAG_BYTES);
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyForHeader(wrappedKey), nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    await writeAtomically(output, temporary => pipeline(
      input.createReadStream({ start: header.length, end: size - TAG_BYTES - 1, autoClose: false }),
      decipher,
      fs.createWriteStream(temporary, { flags: 'wx', mode: 0o600 }),
    ));
  } finally {
    await input.close();
  }
}

// One parser validates and extracts. Copy only regular files and directory names,
// preserving owner execute permission without applying archived ownership or modes.
const EXTRACT_ARCHIVE = String.raw`
import os
import pathlib
import re
import shutil
import sys
import tarfile

archive, destination = sys.argv[1:]
root = pathlib.Path(destination)
seen = set()
total_bytes = 0
with tarfile.open(archive, 'r:gz') as source:
    for member in source:
        if not (member.isfile() or member.isdir()) or member.issparse():
            raise ValueError('Unsupported archive member')
        name = member.name
        if re.search(r'[\\\x00-\x1f\x7f]', name) or name.startswith('/'):
            raise ValueError('Unsafe archive member path')
        relative = name.removeprefix('./')
        if relative in ('', '.'):
            if not member.isdir() or name not in ('.', './'):
                raise ValueError('Invalid archive root')
            relative = '.'
        else:
            parts = relative.split('/')
            if any(part in ('', '.', '..') for part in parts) or re.match(r'^[A-Za-z]:', parts[0]):
                raise ValueError('Unsafe archive member path')
        if relative in seen:
            raise ValueError('Duplicate archive member')
        seen.add(relative)
        total_bytes += member.size
        if len(seen) > 100000 or total_bytes > 2 * 1024**3:
            raise ValueError('Archive exceeds extraction limits')
        target = root / relative
        if member.isdir():
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source.extractfile(member) as data, target.open('xb') as output:
                shutil.copyfileobj(data, output)
            target.chmod(0o700 if member.mode & 0o100 else 0o600)
`;

async function openArchive(payload, destination, decryptArchive) {
  const target = path.resolve(destination);
  if (fs.existsSync(target)) throw new Error('Destination already exists');
  const temporary = await fsp.mkdtemp(path.join(path.dirname(target), '.sealed-extract-'));
  try {
    const archive = path.join(temporary, 'payload.tar.gz');
    const contents = path.join(temporary, 'contents');
    await decryptArchive(payload, archive);
    await fsp.mkdir(contents, { mode: 0o700 });
    const extraction = spawnSync('python3', ['-I', '-c', EXTRACT_ARCHIVE, archive, contents], {
      stdio: 'ignore',
    });
    if (extraction.status !== 0) throw new Error('Archive extraction rejected');
    await fsp.rename(contents, target);
  } finally {
    await fsp.rm(temporary, { recursive: true, force: true });
  }
}

async function main([command, ...args]) {
  if (command === 'encrypt-input' && args.length === 2) {
    return encrypt(args[0], args[1], sourceKey(), INPUT_MAGIC);
  }
  if (command === 'source-url' && args.length === 1) {
    process.stdout.write(readPlan(args[0]).payloadUrl + '\n');
    return;
  }
  if (command === 'decrypt-input' && args.length === 3) {
    const [plan, payload, destination] = args;
    if (await sha256(payload) !== readPlan(plan).payloadSha256) {
      throw new Error('Source payload SHA-256 did not match source plan');
    }
    const key = sourceKey();
    delete process.env.SEALED_SOURCE_KEY;
    return openArchive(payload, destination, (ciphertext, archive) => (
      decrypt(ciphertext, archive, INPUT_MAGIC, wrapped => {
        if (wrapped.length !== 0) throw new Error('Unexpected input envelope key');
        return key;
      })
    ));
  }
  if (command === 'encrypt-output' && args.length === 3) {
    const [plan, archive, payload] = args;
    const recipient = recipientKey(readPlan(plan).recipientPublicKey, crypto.createPublicKey);
    const key = crypto.randomBytes(32);
    return encrypt(archive, payload, key, OUTPUT_MAGIC, crypto.publicEncrypt({ key: recipient, ...OAEP }, key));
  }
  if (command === 'decrypt-output' && args.length === 4) {
    const [plan, privateKey, payload, destination] = args;
    const recipient = recipientKey(fs.readFileSync(privateKey), crypto.createPrivateKey);
    const expected = recipientKey(readPlan(plan).recipientPublicKey, crypto.createPublicKey);
    if (!crypto.createPublicKey(recipient).equals(expected)) throw new Error('Recipient key mismatch');
    return openArchive(payload, destination, (ciphertext, archive) => (
      decrypt(ciphertext, archive, OUTPUT_MAGIC, wrapped => {
        if (wrapped.length !== recipient.asymmetricKeyDetails.modulusLength / 8) {
          throw new Error('Unexpected output envelope key');
        }
        return crypto.privateDecrypt({ key: recipient, ...OAEP }, wrapped);
      })
    ));
  }
  throw new Error('Invalid command or arguments');
}

if (require.main === module) {
  const command = process.argv[2];
  main(process.argv.slice(2)).catch(() => {
    // Paths, payload metadata and cryptographic library details stay out of CI logs.
    const knownCommands = ['source-url', 'encrypt-input', 'decrypt-input', 'encrypt-output', 'decrypt-output'];
    const label = knownCommands.includes(command) ? command : 'sealed command';
    console.error(label + ' failed');
    process.exitCode = 1;
  });
}
