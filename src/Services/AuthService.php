<?php
namespace App\Services;

use App\Database;
use App\Utils\JsonResponse;
use App\Utils\Request;
use App\Config;
use App\Services\Mailer;
use DateTimeZone;
use Exception;
use Dotenv\Dotenv;
use App\Utils\Logger;
use Monolog\Logger as MonologLogger;


class AuthService {
    private Database $db;
    private TokenService $tokenService;
    private Mailer $mailer;

    public function __construct() {
        $this->db = new Database;
        $this->tokenService = new TokenService;
    }

    public function validatePassword($password) {
        $validation = [
        'length' => strlen($password) >= 8 ,
        'number' => preg_match('/\d/', $password),
        'special' => preg_match('/[!@#$%^&*]/', $password),
        'uppercase' => preg_match('/[A-Z]/', $password),
        'lowercase' => preg_match('/[a-z]/', $password),
        ];

        $result = array_filter(array_keys($validation), fn($condition) => !$validation[$condition]);
        if ($result && count($result) >0) {
            Logger::getInstance()->warning('Password validation failed.', ['failed_conditions' => $result]);
            return false;
        }
        return true;
    }

    public function register(array $data): array {
        $email = strtolower(trim($data['email'] ?? ''));
        $password = (string)($data['password'] ?? '');
        $name = filter_var(strtolower(trim($data['username'] ?? '')), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
            Logger::getInstance()->warning('Registration failed: Invalid input.', ['email' => $email]);
            JsonResponse::send(['error' => 'invalid_input'], 422);
        }

        if (!$this -> validatePassword($password)){
            JsonResponse::send(['error' => 'Invalid Password'], 422);
        }
        
        if (strlen($name) < 3 || strlen($name) > 50 || !preg_match('/^[a-zA-Z0-9_-]+$/', $name)) {
            Logger::getInstance()->warning('Registration failed: Invalid username.', ['username' => $name]);
            JsonResponse::send(['error' => 'invalid_username'], 409);
        }

        $pdo = $this->db->getPdo();
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1');
        $stmt->execute([$email, $name]);
        if ($stmt->fetch()) {
            Logger::getInstance()->warning('Registration failed: Email or username taken.', ['email' => $email, 'username' => $name]);
            JsonResponse::send(['error' => 'email_or_username_taken'], 409);
        }

        $options = ['memory_cost' => 1 << 16, 'time_cost' => 3, 'threads' => 2];
        $hash = password_hash($password, PASSWORD_ARGON2ID, $options);
        $stmt = $pdo->prepare('INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)');
        $stmt->execute([$email, $hash, $name]);
        $user_id = (int)$pdo->lastInsertId();
        Logger::getInstance()->info('New user created.', ['user_id' => $user_id, 'email' => $email]);

        $r = $pdo->prepare("SELECT id FROM roles WHERE slug = 'user' LIMIT 1");
        $r->execute();
        $row = $r->fetch();
        if ($row) {
            $pdo->prepare('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)')->execute([$user_id, $row['id']]);
        }

        $access = $this->tokenService->issueAccessToken(['id' => $user_id], ['user']);
        $refresh = $this->issueRefreshToken($user_id);
        $data = ['user_id' => $user_id, 'email' => $email];
        $result = $this->sendConfirmationEmail($data);
        if($result) {
            Logger::getInstance()->info('Registration successful, confirmation email sent.', ['user_id' => $user_id]);
            return ['access_token' => $access, 'expires_in' => Config::get('JWT_TTL')];
        } else {
            Logger::getInstance()->error('Registration successful, but confirmation email failed.', ['user_id' => $user_id]);
            JsonResponse::send(['error' => 'Could not send the confirmation Email. Please contact your Administrator.'], 409);
        }

    }

    public function login(array $data): array {
        $email = strtolower(trim($data['email'] ?? ''));
        $password = (string)($data['password'] ?? '');
        $pdo = $this->db->getPdo();
        $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            Logger::getInstance()->warning('Login failed: Invalid credentials.', ['email' => $email]);
            usleep(200000);
            JsonResponse::send(['error' => 'No user found or wrong password'], 401);
        }

        if (!$user['email_verified_at']){
            Logger::getInstance()->warning('Login failed: Email not verified.', ['email' => $email]);
            JsonResponse::send(['error' => 'email not yet verified'], 401);
        }
        $scopes = ['user'];
        
        $r = $pdo->prepare('SELECT 1 FROM user_roles ur JOIN roles ro ON ro.id = ur.role_id WHERE ur.user_id = ? AND ro.slug = ? LIMIT 1');
        $r->execute([$user['id'], 'admin']);
        if ($r->fetch()) {
            $scopes[] = 'admin';
        }

        $access = $this->tokenService->issueAccessToken(['id' => $user['id']], $scopes);
        $refresh = $this->issueRefreshToken((int)$user['id']);

        // Set HTTP-only cookie
        Logger::getInstance()->info('User authenticated, issuing tokens.', ['user_id' => $user['id']]);
        setcookie(
            'refresh_token',
            $refresh,
            [
                'expires' => time() + (Config::get('REFRESH_TTL_DAYS') * 24 * 60 * 60),
                'path' => '/',
                'httponly' => true,
                'secure' => Config::get('COOKIE_SECURE'),
                'samesite' => Config::get('COOKIE_SAMESITE')
            ]
        );
        return ['access_token' => $access, 'expires_in' => Config::get('JWT_TTL')];
    }

    public function logout() {
        try {
            $token = Request::getBearerToken();
            $pdo = $this->db->getPdo();
            $pdo->beginTransaction();

            if ($token) {
                $claims = $this->tokenService->decodeAccessToken($token);
                
                $pdo = $this->db->getPdo();
                $stmt = $pdo->prepare('INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, FROM_UNIXTIME(?))');
                $stmt->execute([$claims->jti, $claims->exp]);
                if ($stmt->rowCount() === 0) {
                    throw new Exception('Failed to insert revoked access token.');
                }
            }
            $refreshToken = $_COOKIE['refresh_token'] ?? null;
            if ($refreshToken) {
                $hashedRefreshToken = hash('sha256', $refreshToken);

                // Step 2: Update refresh token to mark it as revoked
                $updateStmt = $pdo->prepare('UPDATE refresh_tokens SET revoked_at = UTC_TIMESTAMP() WHERE token_hash = ? AND revoked_at IS NULL');
                $updateStmt->execute([$hashedRefreshToken]);
                
                if ($updateStmt->rowCount() === 0) {
                    throw new Exception('Failed to update refresh token or it was already revoked.');
                }
            }
            $pdo->commit();
            Logger::getInstance()->info('User logout successful.', ['user_id' => Request::$user->sub ?? 'N/A']);
            // Unset the refresh token cookie regardless of access token presence
            setcookie('refresh_token', '',
            [
                    'expires' =>  time() - 3600,
                    'path' => '/',
                    'httponly' => true,
                    'secure' => Config::get('COOKIE_SECURE'),
                    'samesite' => Config::get('COOKIE_SAMESITE')
            ]);

            JsonResponse::send('You have successfully logged out', 201);
        } catch (\Throwable $th) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            Logger::getInstance()->error('Logout failed.', ['error' => $th->getMessage()]);
            JsonResponse::send(['error' => $th->getMessage()], 500);
        }
    }

    private function issueRefreshToken(int $user_id): string {
        $pdo = $this->db->getPdo();
        $token = bin2hex(random_bytes(32));
        $hash = hash('sha256', $token);
        $expires = (new \DateTime('now', new \DateTimeZone('UTC') ))->modify('+' . Config::get('REFRESH_TTL_DAYS') . ' days')->format('Y-m-d H:i:s');
        $stmt = $pdo->prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address) VALUES (?, ?, ?, ?, INET6_ATON(?))');
        $stmt->execute([$user_id, $hash, $expires, $_SERVER['HTTP_USER_AGENT'] ?? null, $_SERVER['REMOTE_ADDR'] ?? null]);
        Logger::getInstance()->info('New refresh token issued.', ['user_id' => $user_id, 'expires_at' => $expires]);
        return $token;
    }

    public function rotateAccessToken(string $incoming): ?array {
                
        $pdo = $this->db->getPdo();
        $hash = hash('sha256', $incoming);
        $pdo->beginTransaction();

        $stmt = $pdo->prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > UTC_TIMESTAMP() FOR UPDATE');
        $stmt->execute([$hash]);
        $row = $stmt->fetch();

        if (!$row) {
            Logger::getInstance()->warning('Refresh token rotation failed: Token not found, revoked, or expired.', ['token_hash' => $hash]);
            $pdo->rollBack();
            return null;
        }

        $pdo->prepare('UPDATE refresh_tokens SET revoked_at = UTC_TIMESTAMP() WHERE id = ?')->execute([$row['id']]);

        $new_token = bin2hex(random_bytes(32));
        $new_hash = hash('sha256', $new_token);
        $expires = (new \DateTime('now', new \DateTimeZone('UTC')))->modify('+' . Config::get('REFRESH_TTL_DAYS') . ' days')->format('Y-m-d H:i:s');
        $pdo->prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address) VALUES (?,?,?,?,INET6_ATON(?))')
            ->execute([$row['user_id'], $new_hash, $expires, $_SERVER['HTTP_USER_AGENT'] ?? null, $_SERVER['REMOTE_ADDR'] ?? null]);
        $new_id = (int)$pdo->lastInsertId();
        $pdo->prepare('UPDATE refresh_tokens SET replaced_by = ? WHERE id = ?')->execute([$new_id, $row['id']]);

        $pdo->commit();
        Logger::getInstance()->info('Access token rotated.', ['user_id' => $row['user_id'], 'new_refresh_token_id' => $new_id]);
        
        // Set new HTTP-only cookie
        setcookie(
            'refresh_token',
            $new_token,
            [
                'expires' => time() + (Config::get('REFRESH_TTL_DAYS') * 24 * 60 * 60),
                'path' => '/',
                'httponly' => true,
                'secure' => Config::get('COOKIE_SECURE'),
                'samesite' => Config::get('COOKIE_SAMESITE')
            ]
        );

        $access = $this->tokenService->issueAccessToken(['id' => $row['user_id']], ['user']); 
        return ['access_token' => $access, 'expires_in' => Config::get('JWT_TTL')];
    }
    
    public function revokeRefreshToken(string $incoming): bool {
        $pdo = $this->db->getPdo();
        $hash = hash('sha256', $incoming);
        $stmt = $pdo->prepare('UPDATE refresh_tokens SET revoked_at = UTC_TIMESTAMP() WHERE token_hash = ? AND revoked_at IS NULL');
        $stmt->execute([$hash]);
        $result = $stmt->rowCount() > 0;
        if ($result) {
            Logger::getInstance()->info('Refresh token revoked successfully.', ['token_hash' => $hash]);
        } else {
            Logger::getInstance()->warning('Failed to revoke refresh token.', ['token_hash' => $hash]);
        }
        return $result;
    }

    public function getUserById(int $id): ?array {
        $pdo = $this->db->getPdo();
        $stmt = $pdo->prepare('SELECT id, email, username, created_at FROM users WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $user = $stmt->fetch();
        if ($user) {
            Logger::getInstance()->info('User found.', ['user_id' => $id]);
        } else {
            Logger::getInstance()->warning('User not found.', ['user_id' => $id]);
        }
        return $user ?: null;
    }

    public function getUsers(): array {
        $pdo = $this->db->getPdo();
        $rows = $pdo->query('SELECT id,email,created_at FROM users ORDER BY id DESC LIMIT 100')->fetchAll();
        Logger::getInstance()->info('Retrieved user list.');
        return $rows;
    }

    public function sendConfirmationEmail(array $data): bool {
        $this->mailer = new Mailer;
        $user_email = strtolower(trim($data['email'] ?? ''));
        $emailValidation = filter_var($user_email, FILTER_VALIDATE_EMAIL);
        if (!$emailValidation){
            Logger::getInstance()->warning('Failed to send confirmation email: Invalid email.', ['email' => $user_email]);
            JsonResponse::send(['error' => 'invalid_input'], 422);
        }
        $user_id = strtolower(trim($data['user_id'] ?? ''));
        
        $pdo = $this->db->getPdo();
        if(!$user_id) {
            $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? AND email_verified_at IS NULL LIMIT 1');
            $stmt->execute([$user_email]);
            $user = $stmt->fetch() ?: null;
            $user_id = $user['id'] ?? null;
        }
        
        $userIdValidation = filter_var($user_id, FILTER_VALIDATE_INT);
        if (!$userIdValidation || $user_id <= 0){
            Logger::getInstance()->warning('Failed to send confirmation email: Invalid user ID.', ['user_id' => $user_id]);
            usleep(200000);
            JsonResponse::send(['error' => 'invalid_user_id'], 422);
        }
        
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $stmt = $pdo->prepare('INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)');
        $expiresAt = new \DateTime('now', new \DateTimeZone('UTC'))
                    -> modify('+1 hour')
                    ->format('Y-m-d H:i:s');
        $stmt->execute([$user_id, $tokenHash, $expiresAt]);
        $id = (int)$pdo->lastInsertId();

        if (!$id){
            Logger::getInstance()->error('Failed to insert email confirmation token into database.', ['user_id' => $user_id]);
            return false;
        }
        
        $result = $this->mailer->sendEmailConfirmation($user_email, $token, $user_id);
        if ($result) {
            Logger::getInstance()->info('Confirmation email sent successfully.', ['email' => $user_email]);
            return true;
        } else {
            Logger::getInstance()->error('Failed to send confirmation email via mailer.', ['email' => $user_email]);
            return false;
        }
    }

    
    public function confirmEmail(): bool {

        $token = filter_input(INPUT_GET, 'token', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $userId = filter_input(INPUT_GET,'user_id', FILTER_SANITIZE_NUMBER_INT);
        if (empty($token)){
            Logger::getInstance()->warning('Email confirmation failed: Missing token.');
            JsonResponse::send(['error' => 'invalid_token'], 422);
        }
        if (!$userId || $userId <= 0){
            Logger::getInstance()->warning('Email confirmation failed: Invalid user ID.');
            JsonResponse::send(['error' => 'invalid_user_id'], 422);
        }
        
        
        $token_hash = hash('sha256', $token);
        $pdo = $this->db->getPdo();
        
        $pdo->beginTransaction();
        
        try {
            $stmt = $pdo->prepare('SELECT * FROM email_verification_tokens WHERE user_id = ? AND revoked_at IS NULL AND expires_at > UTC_TIMESTAMP() FOR UPDATE');
            $stmt->execute([$userId]);
            $token_record = $stmt->fetch();

            if (!$token_record) {
                Logger::getInstance()->warning('Email confirmation failed: Token not found, revoked, or expired.', ['user_id' => $userId]);
                $pdo->rollBack();
                return false;
            }

            if ($token_record['token_hash'] !== $token_hash) {
                Logger::getInstance()->warning('Email confirmation failed: Token hash mismatch.', ['user_id' => $userId]);
                $pdo->rollBack();
                return false;
            }

            $stmt = $pdo->prepare('SELECT email_verified_at FROM users WHERE id = ? LIMIT 1');
            $stmt->execute([$userId]);
            $user = $stmt->fetch();

            if ($user && $user['email_verified_at'] !== null) {
                Logger::getInstance()->info('Email already verified, revoking old token.', ['user_id' => $userId]);
                $revoke_stmt = $pdo->prepare('UPDATE email_verification_tokens SET revoked_at = UTC_TIMESTAMP() WHERE id = ?');
                $revoke_stmt->execute([$token_record['id']]);
                $pdo->commit();
                return true;
            }

            $user_update_stmt = $pdo->prepare('UPDATE users SET email_verified_at = UTC_TIMESTAMP() WHERE id = ?');
            $user_update_stmt->execute([$userId]);

            $revoke_stmt = $pdo->prepare('UPDATE email_verification_tokens SET revoked_at = UTC_TIMESTAMP() WHERE id = ?');
            $revoke_stmt->execute([$token_record['id']]);
            
            $pdo->commit();
            Logger::getInstance()->info('Email confirmed successfully.', ['user_id' => $userId]);
            return true;
            
        } catch (\PDOException $e) {
            $pdo->rollBack();
            Logger::getInstance()->error('Error confirming email.', ['user_id' => $userId, 'error' => $e->getMessage()]);
            return false;
        }
    }


    public function requestPasswordReset(array $data) {
        $this->mailer = new Mailer;
        $email = strtolower(trim($data['email'] ?? ''));
        $validation = filter_var($email, FILTER_VALIDATE_EMAIL);
        if (!$validation){
            Logger::getInstance()->warning('Password reset request failed: Invalid email.', ['email' => $email]);
            JsonResponse::send(['error' => 'invalid_input'], 422);
        }

        $pdo = $this->db->getPdo();
        $stmt = $pdo->prepare('SELECT id, email FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user) {
            Logger::getInstance()->warning('Password reset request for non-existent email.', ['email' => $email]);
            return "The reset link was successfully sent to  $email";
        }

        $token = bin2hex(random_bytes(32));
        $hash = hash('sha256', $token);
        $expires = (new \DateTime('now', new \DateTimeZone('UTC')))->modify('+1 hour')->format('Y-m-d H:i:s');
        
        $stmt = $pdo->prepare('UPDATE users SET reset_token_hash = ?, reset_token_expires_at = ? WHERE id = ?');
        $stmt->execute([$hash, $expires, $user['id']]);

        $link = "http://localhost:8000/reset-password.html?token={$token}";
        
        $x = $this->mailer->sendEmail($user['email'], "reset password confirmation",$link);
        if ($x) {
            Logger::getInstance()->info('Password reset email sent successfully.', ['email' => $email]);
            return "The reset link was successfully sent to  $email";   
        } else {
            Logger::getInstance()->error('Failed to send password reset email via mailer.', ['email' => $email]);
            JsonResponse::send(['error' => 'email could not be sent. try again.'], 500);
        }
        
    }

    public function resetPassword(array $data): bool {
        $token = strtolower(trim($data['token'] ?? ''));
        $password = (string)($data['password'] ?? '');
        if (!$token){
            Logger::getInstance()->warning('Password reset failed: Missing token.');
            JsonResponse::send(['error' => 'invalid_token'], 422);
        }
        if (!$this->validatePassword($password)){
            JsonResponse::send(['error' => 'invalid_password'], 422);
        }
        
        $pdo = $this->db->getPdo();
        $hash = hash('sha256', $token);
        $pdo->beginTransaction();
        $stmt = $pdo->prepare('SELECT id FROM users WHERE reset_token_hash = ? AND reset_token_expires_at > UTC_TIMESTAMP() FOR UPDATE');
        $stmt->execute([$hash]);
        $user = $stmt->fetch();

        if (!$user) {
            $pdo->rollBack();
            Logger::getInstance()->warning('Password reset failed: Invalid or expired token.', ['token_hash' => $hash]);
            JsonResponse::send(['error' => 'User not found'], 422);
        }

        $options = ['memory_cost' => 1 << 16, 'time_cost' => 3, 'threads' => 2];
        $new_password_hash = password_hash($password, PASSWORD_ARGON2ID, $options);

        $stmt = $pdo->prepare('UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_token_expires_at = NULL WHERE id = ?');
        $stmt->execute([$new_password_hash, $user['id']]);

        $pdo->commit();
        Logger::getInstance()->info('Password reset successful.', ['user_id' => $user['id']]);
        return true;
    }

    public function googleLogin() {
        $clientId = $_ENV['OAUTH_GOOGLE_ID'];
        $redirectUri = $_ENV['GOOGLE_REDIRECT_URI'];
        $scope = 'email profile';
        $authUrl = "https://accounts.google.com/o/oauth2/v2/auth?scope=" . urlencode($scope) . "&response_type=code&client_id=" . $clientId . "&redirect_uri=" . urlencode($redirectUri);
        header('Location: ' . $authUrl);
        exit;
    }

    public function googleCallback($code) {
       try {
            Logger::getInstance()->info('Google OAuth callback received, exchanging code for tokens.');
            // Step 1: Exchange code for access token and ID token
            $clientId = $_ENV['OAUTH_GOOGLE_ID'];
            $clientSecret = $_ENV['OAUTH_GOOGLE_SECRET'];
            $redirectUri = $_ENV['GOOGLE_REDIRECT_URI'];
            
            $url = 'https://oauth2.googleapis.com/token';
            $data = [
                'code' => $code,
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ];
            
            $options = [
                'http' => [
                    'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                    'method'  => 'POST',
                    'content' => http_build_query($data),
                ],
            ];
            
            $context  = stream_context_create($options);
            $response = file_get_contents($url, false, $context);
            $result = json_decode($response, true);
            
            if (!isset($result['id_token'])) {
                Logger::getInstance()->error('Google OAuth failed: No ID token received.');
                throw new Exception('Failed to get ID token from Google.');
            }
            
            $idToken = $result['id_token'];
            
            // Step 2: Decode the ID token to get user information
            $parts = explode('.', $idToken);
            $payload = base64_decode($parts[1]);
            $userProfile = json_decode($payload, true);
            
            $email = $userProfile['email'];
            $username = $userProfile['name'];
            
            // Step 3: Find or create the user in your database
            $pdo = $this->db->getPdo();
            $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            if (!$user) {
                Logger::getInstance()->info('Google OAuth: Creating new user.', ['email' => $email]);
                $stmt = $pdo->prepare('INSERT INTO users (username, email, email_verified_at, password_hash) VALUES (?, ?, ?, ?)');
                $stmt->execute([
                    $username,
                    $email,
                    (new \DateTime())->format('Y-m-d H:i:s'),
                    'google_account'
                ]);
                
                $userId = $pdo->lastInsertId();
                $user = $this->getUserById((int)$userId);
            }
            
            $scopes = ['user'];
            
            $r = $pdo->prepare('SELECT 1 FROM user_roles ur JOIN roles ro ON ro.id = ur.role_id WHERE ur.user_id = ? AND ro.slug = ? LIMIT 1');
            $r->execute([$user['id'], 'admin']);
            if ($r->fetch()) {
                $scopes[] = 'admin';
            }
            // Step 4: Create a session and return tokens
            $tokens = $this->tokenService->issueAccessToken(['id' => $user['id']], $scopes);
            $refresh = $this->issueRefreshToken((int)$user['id']);
            Logger::getInstance()->info('Google OAuth successful, returning tokens.', ['user_id' => $user['id']]);

            // Set HTTP-only cookie
            setcookie(
                'refresh_token',
                $refresh,
                [
                    'expires' => time() + (Config::get('REFRESH_TTL_DAYS') * 24 * 60 * 60),
                    'path' => '/',
                    'httponly' => true,
                    'secure' => Config::get('COOKIE_SECURE'),
                    'samesite' => Config::get('COOKIE_SAMESITE')
                ]
            );

            return ['access_token' => $tokens, 'expires_in' => Config::get('JWT_TTL'), 'user' => $user];
            
        } catch (Exception $e) {
            Logger::getInstance()->error('Google OAuth callback failed.', ['error' => $e->getMessage()]);
            JsonResponse::send(['error' => 'Authentication failed. Please try again.'], 400);
        }
    }

}
