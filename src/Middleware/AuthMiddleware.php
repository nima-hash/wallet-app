<?php
namespace App\Middleware;

use App\Services\TokenService;
use App\Utils\JsonResponse;
use App\Utils\Request;
use App\Database;
use Exception;
use App\Utils\Logger;
use Monolog\Logger as MonologLogger;

class AuthMiddleware {
    private TokenService $tokenService;
    private Database $db;

    public function __construct() {
        $this->db = new Database();
        $this->tokenService = new TokenService();
    }

    public function requireAuth() {
        $token = Request::getBearerToken();
        if (!$token) {
            Logger::getInstance()->warning('Authentication failed: Missing token.');
            JsonResponse::send(['error' => 'missing_token'], 401);
        }

        try {
            $claims = $this->tokenService->decodeAccessToken($token);

            // Check if the token's JTI is in the revocation list
            $pdo = $this->db->getPdo();
            $stmt = $pdo->prepare('SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > UTC_TIMESTAMP() LIMIT 1');
            $stmt->execute([$claims->jti]);
            if ($stmt->fetch()) {
                Logger::getInstance()->warning('Authentication failed: Token is revoked.', ['jti' => $claims->jti, 'user_id' => $claims->sub]);
                JsonResponse::send(['error' => 'token_revoked'], 401);
            }
            $this->tokenService->verifyAccessToken($token);
            
            Logger::getInstance()->info('Authentication successful.', ['user_id' => $claims->sub, 'token_jti' => $claims->jti]);
            Request::$user = $claims; // Store user claims for the controller
            return $claims;
        } catch (Exception $e) {
            Logger::getInstance()->error('Authentication failed: Invalid token.', ['error_message' => $e->getMessage()]);
            JsonResponse::send(['error' => $e->getMessage()], 401);
        }
    }

    public function requireRole(string $role) {
        $claims = $this->requireAuth();
        $user_id = (int)$claims->sub;
        $pdo = $this->db->getPdo();
        $stmt = $pdo->prepare('SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.slug = ? LIMIT 1');
        $stmt->execute([$user_id, $role]);
        if (!$stmt->fetch()) {
            Logger::getInstance()->warning('Authorization failed: Insufficient role.', ['user_id' => $user_id, 'required_role' => $role]);
            JsonResponse::send(['error' => 'insufficient_role'], 403);
        }
        Logger::getInstance()->info('Authorization successful.', ['user_id' => $user_id, 'role' => $role]);
        return $claims;
    }
}
