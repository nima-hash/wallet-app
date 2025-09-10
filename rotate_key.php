<?php
// rotate_key.php - run from CLI: php rotate_key.php newkid
if (PHP_SAPI !== 'cli') { echo "Run from CLI\n"; exit; }
if ($argc < 2) { echo "Usage: php rotate_key.php <kid>\n"; exit(1); }
$kid = $argv[1];
$keys_dir = __DIR__ . '/keys';
@mkdir($keys_dir, 0700, true);
$priv = $keys_dir . '/' . $kid . '.pem';
$pub  = $keys_dir . '/' . $kid . '.pub.pem';
echo "Generating RSA 2048-bit keypair for kid: $kid\n";
exec("openssl genrsa -out " . escapeshellarg($priv) . " 2048", $o, $ret);
if ($ret !== 0) { echo "openssl genrsa failed\n"; exit(1); }
exec("openssl rsa -in " . escapeshellarg($priv) . " -pubout -out " . escapeshellarg($pub), $o2, $ret2);
if ($ret2 !== 0) { echo "openssl rsa pubout failed\n"; exit(1); }
chmod($priv, 0600);
echo "Keys written: $priv and $pub\n";
echo "Now update your env: CURRENT_KID=$kid (or update your server env and restart)\n";
echo "Your JWKS will include this public key at /.well-known/jwks.json\n";

// Rotation flow:

// Run php rotate_key.php kid2 (creates keys/kid2.pem and keys/kid2.pub.pem).

// Set CURRENT_KID=kid2 in your environment and restart PHP-FPM (or reload).

// New tokens will be signed with kid2; old tokens signed with kid1 remain verifiable using published kid1.pub.pem in JWKS. Keep old public keys available until all tokens signed by old key expire.