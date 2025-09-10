<?php
namespace App\Utils;

use App\Utils\Logger;
use Monolog\Logger as MonologLogger;

class Request {
    public static $user = null;

    public static function getMethod(): string {
        return $_SERVER['REQUEST_METHOD'] ?? 'GET';
    }

    public static function getPath(): string {
        return parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    }

    public static function getJsonBody(): array {
        $body = file_get_contents('php://input');
        if (!$body) {
            Logger::getInstance()->info('Empty JSON body received.');
            return [];
        }
        $d = json_decode($body, true);
        if (is_array($d)) {
            Logger::getInstance()->info('JSON body received.', ['body' => $d]);
            return $d;
        }
        Logger::getInstance()->warning('Invalid JSON body received.');
        return [];
    }

    public static function getBearerToken(): ?string {
        $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/Bearer\s+(\S+)/i', $hdr, $m)) {
            Logger::getInstance()->debug('Bearer token found in request header.');
            return $m[1];
        }
        Logger::getInstance()->debug('No Bearer token found in request header.');
        return null;
    }

    public static function getParam(string $name): ?string {
        return $_GET[$name] ?? null;
    }
}
