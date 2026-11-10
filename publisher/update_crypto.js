// Ed25519 keys stay on the publisher's Mac. Clients and servers need only the public key.
const crypto = require('node:crypto');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', s => input += s);
process.stdin.on('end', () => {
  try {
    const p = JSON.parse(input);
    if (p.op === 'keygen') {
      const k = crypto.generateKeyPairSync('ed25519');
      process.stdout.write(JSON.stringify({privateKey:k.privateKey.export({type:'pkcs8',format:'pem'}),publicKey:k.publicKey.export({type:'spki',format:'pem'})}));
    } else if (p.op === 'sign') {
      process.stdout.write(JSON.stringify({signature:crypto.sign(null,Buffer.from(p.payload,'base64'),p.key).toString('base64')}));
    } else if (p.op === 'verify') {
      const key = crypto.createPublicKey(p.key);
      if (key.asymmetricKeyType !== 'ed25519' || !crypto.verify(null,Buffer.from(p.payload,'base64'),key,Buffer.from(p.signature,'base64'))) throw Error('invalid signature');
      process.stdout.write('{"ok":true}');
    } else throw Error('unknown operation');
  } catch (_) { process.stderr.write('数字签名操作失败'); process.exitCode=1; }
});
