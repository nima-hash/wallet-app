<?php
namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;
use App\Config;
use App\Utils\Logger;

class TokenService {
    private function loadPrivateKey(string $kid): string {
        $path = Config::get('KEYS_DIR') . '/' . $kid . '.pem';
        if (!file_exists($path)) {
            Logger::getInstance()->error('Private key not found.', ['path' => $path]);
            throw new Exception('Private key not found: ' . $path);
        }
        return file_get_contents($path);
    }

    private function loadPublicKey(string $kid): string {
        $path = Config::get('KEYS_DIR') . '/' . $kid . '.pub.pem';
        if (!file_exists($path)) {
            Logger::getInstance()->error('Public key not found.', ['path' => $path]);
            throw new Exception('Public key not found: ' . $path);
        }
        return file_get_contents($path);
    }

    public function issueAccessToken(array $user, array $scopes = []): string {
        $now = time();
        $payload = [
            'iss' => Config::get('JWT_ISS'),
            'aud' => Config::get('JWT_AUD'),
            'sub' => (string)$user['id'],
            'jti' => bin2hex(random_bytes(8)),
            'iat' => $now,
            'exp' => $now + Config::get('JWT_TTL'),
            'scope' => implode(' ', $scopes)
        ];
        
        $priv = $this->loadPrivateKey(Config::get('CURRENT_KID'));
        
        $token = JWT::encode($payload, $priv, 'RS256', Config::get('CURRENT_KID'));
        Logger::getInstance()->info('Access token issued.', ['user_id' => $user['id'], 'jti' => $payload['jti'], 'scopes' => $scopes]);
        return $token;
    }

    public function verifyAccessToken(string $jwt): object {
        try {
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                Logger::getInstance()->warning('JWT verification failed: Invalid token format.');
                throw new Exception("Invalid token format.");
            }
            $hdr = json_decode(base64_decode($parts[0]), true);

            $kid = $hdr['kid'] ?? Config::get('CURRENT_KID');
            $pub = $this->loadPublicKey($kid);

            $claims = JWT::decode($jwt, new Key($pub, 'RS256'));
            Logger::getInstance()->info('Access token verified.', ['user_id' => $claims->sub, 'jti' => $claims->jti]);
            return $claims;
        } catch (Exception $e) {
            Logger::getInstance()->error('Access token verification failed.', ['error_message' => $e->getMessage()]);
            throw $e; // Re-throw the exception for the caller to handle
        }
    }

    public function decodeAccessToken(string $jwt): object {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            Logger::getInstance()->warning('Token decoding failed: Invalid token format.');
            throw new Exception("Invalid token format.");
        }
        $payload = base64_decode($parts[1]);
        $decoded_payload = json_decode($payload);
        Logger::getInstance()->debug('Access token decoded successfully.');
        return $decoded_payload;
    }
}
