<?php
namespace App;

use App\Controllers\AuthController;
use App\Middleware\AuthMiddleware;
use App\Utils\JsonResponse;
use App\Utils\Request;
use App\Utils\Logger;


class Routes {
    public function handleRequest() {
        $method = Request::getMethod();
        $path = Request::getPath();
        
        Logger::getInstance()->info("Handling request: {$method} {$path}");

        $authController = new AuthController();
        $authMiddleware = new AuthMiddleware();

        switch ($path) {
            case '/api/register':
                if ($method === 'POST') {
                    $authController->register();
                }
                break;
            case '/api/login':
                if ($method === 'POST') {
                    Logger::getInstance()->info('Login request received.');
                    $authController->login();
                }
                break;
            case '/api/refresh':
                if ($method === 'POST') {
                    $authController->refresh();
                }
                break;
            case '/api/logout':
                if ($method === 'POST') {
                    $authController->logout();
                }
                break;
            case '/api/password/forgot':
                if ($method === 'POST') {
                    $authController->forgotPassword();
                }
                break;
            case '/api/password/reset':
                if ($method === 'POST') {
                    $authController->resetPassword();
                }
                break;
            case '/api/resend-confirmation-email':
                if ($method === 'POST') {
                    $authController->resendConfirmationEmail();
                }
                break;
            case '/api/me':
                if ($method === 'GET') {
                    $authMiddleware->requireAuth();
                    $authController->me();
                }
                break;
            case '/api/admin/users':
                if ($method === 'GET') {
                    $authMiddleware->requireRole('admin');
                    $authController->getUsers();
                }
                break;
            case '/confirm-email':
                if ($method === 'GET') {
                    $authController->confirmEmail();
                }
                break;
            case '/api/login/google':
                if ($method === 'GET') {
                    $authController->googleLogin();
                }
                break;
            case '/api/admin/users':
                if ($method === 'GET') {
                    $authMiddleware->requireRole('admin');
                    $authController->getUsers();
                }
                break;
            case '/api/login/google/callback':
                if ($method === 'GET') {
                    $authController->googleCallback();
                }
                break;
            default:
                Logger::getInstance()->warning("Route not found: {$method} {$path}");
                JsonResponse::send(['error' => 'Not Found'], 404);
                break;
        }
    }
}
