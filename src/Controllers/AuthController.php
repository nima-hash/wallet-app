<?php
namespace App\Controllers;

use App\Services\AuthService;
use App\Utils\JsonResponse;
use App\Utils\Request;
use Exception;
use App\Utils\Logger;




class AuthController {
    private AuthService $authService;
    

    public function __construct() {
        $this->authService = new AuthService();
    }

    public function register() {
        $data = Request::getJsonBody();  
        try {
            $response = $this->authService->register($data);
            Logger::getInstance()->info('User registered successfully.', ['email' => $data['email']]);
            JsonResponse::send($response, 201);
        } catch (\Exception $e) {
            Logger::getInstance()->warning('Registration failed.', ['email' => $data['email'], 'error' => $e->getMessage()]);
            JsonResponse::send(['error' => $e->getMessage()], 400);
        }
    }

    public function login() {
        
        $data = Request::getJsonBody();
        try {
            $response = $this->authService->login($data);
            Logger::getInstance()->info('User logged in successfully.', ['email' => $data['email']]);
            JsonResponse::send($response);
        } catch (\Exception $e) {
            Logger::getInstance()->warning('Login failed.', ['email' => $data['email'], 'error' => $e->getMessage()]);
            JsonResponse::send(['error' => $e->getMessage()], 400);
        }
    }

    public function googleCallback() {
        $code = Request::getParam('code');
        if (!$code) {
            Logger::getInstance()->warning('Google OAuth callback failed.', ['error' => 'No authorization code received.']);
            JsonResponse::send(['error' => 'Authentication failed or user denied access.'], 400);
        }
        try {
            $response = $this->authService->googleCallback($code);
            Logger::getInstance()->info('Google OAuth login successful.', ['user' => $response['user']['email']]);
            unset($response['user']);
            header('Location: /dashboard.php#access_token=' . $response['access_token']);
            exit;
        } catch (Exception $e) {
            Logger::getInstance()->error('Google OAuth callback failed.', ['error' => $e->getMessage()]);
            JsonResponse::send(['error' => 'Authentication failed. Please try again.'], 400);
        }
    }

    public function googleLogin() {
        Logger::getInstance()->info('Initiating Google OAuth login.');
        try {
            $this->authService->googleLogin();
        } catch (Exception $e) {
            Logger::getInstance()->error('Google login failed to redirect.', ['error' => $e->getMessage()]);
            JsonResponse::send(['error' => 'Google login failed. Please check your configuration.'], 500);
        }
    }

    public function forgotPassword() {
                $data = Request::getJsonBody();
        try {
            $response = $this->authService->requestPasswordReset($data);
            Logger::getInstance()->info('Password reset request sent.', ['email' => $data['email']]);
            JsonResponse::send($response, 200);
        } catch (\Exception $e) {
            Logger::getInstance()->error('Password reset request failed.', ['email' => $data['email'], 'error' => $e->getMessage()]);
            JsonResponse::send(['error' => $e->getMessage()], 500);
        }
    }

    public function resetPassword() {
        $data = Request::getJsonBody();
        try {
            $response = $this->authService->resetPassword($data);
            Logger::getInstance()->info('Password reset successfully.');
            JsonResponse::send('The password is successfully changed.', 200);
        } catch (\Exception $e) {
            Logger::getInstance()->error('Password reset failed.', ['error' => $e->getMessage()]);
            JsonResponse::send('Something went wrong. please try again.', 500);
        }
    }

    public function refresh() {
        $refreshToken = $_COOKIE['refresh_token'] ?? null;
        if (!$refreshToken) {
            Logger::getInstance()->warning('Refresh token missing from cookie.');
            JsonResponse::send(['error' => 'missing_refresh'], 400);
        }
        
        try {
            $accessToken = $this->authService->rotateAccessToken($refreshToken);
            Logger::getInstance()->info('Access token rotated successfully.');
            JsonResponse::send($accessToken);
        } catch (\Exception $e) {
            Logger::getInstance()->warning('Failed to rotate access token.', ['error' => $e->getMessage()]);
            JsonResponse::send(['error' => 'invalid_refresh'], 401);
        }
    }

    public function logout() {
        try {
            $this->authService->logout();
            Logger::getInstance()->info('User logged out successfully.');
            JsonResponse::send('You have successfully loged out', 204);
        } catch (\Throwable $th) {
            Logger::getInstance()->error('Logout failed.', ['error' => $th->getMessage()]);
            JsonResponse::send($th->getMessage(), 500);
        }       
    }

    public function me() {
        $claims = Request::$user;
        $user = $this->authService->getUserById((int)$claims->sub);
        Logger::getInstance()->info('User data retrieved successfully.', ['user_id' => $claims->sub]);
        JsonResponse::send(['user' => $user, 'scope' => ($claims->scope ?? '')]);
    }
        
    public function getUsers() {
        $users = $this->authService->getUsers();
        Logger::getInstance()->info('User list accessed by admin.');
        JsonResponse::send(['users' => $users]);
    }

    public function confirmEmail(): void
    {
        $success = $this->authService->confirmEmail();
        
        if ($success) {
            Logger::getInstance()->info('Email confirmed successfully.', ['token' => Request::getParam('token')]);
            header('Location: /email-confirmed.html');
        } else {
            Logger::getInstance()->warning('Email confirmation failed.', ['token' => Request::getParam('token')]);
            header('Location: /email-confirmation-failed.html');
        }
        exit;
    }
    
    public function resendConfirmationEmail(): void
    {
        $data = Request::getJsonBody();  
        try {
            $success = $this->authService->sendConfirmationEmail($data);
            Logger::getInstance()->info('Confirmation email resent successfully.', ['email' => $data['email']]);
            header('Location: /email-confirmation-sent.html');
            exit;
        } catch (\Exception $e) {
            Logger::getInstance()->error('Failed to resend confirmation email.', ['email' => $data['email'], 'error' => $e->getMessage()]);
            JsonResponse::send(['error' => 'Failed to send confirmation email. Please try again.'], 500);
        }
    }
}