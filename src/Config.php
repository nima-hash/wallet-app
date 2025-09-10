<?php
// src/Config.php
namespace App;

use Dotenv\Dotenv;

class Config {
    private static ?array $config = null;

    public static function load() {
        if (self::$config !== null) {
            return;
        }

        $dotenv = Dotenv::createImmutable(__DIR__ . '/../');
        $dotenv->load();

        self::$config = [
            'DB_HOST' => $_ENV['DB_HOST'] ?? '127.0.0.1',
            'DB_PORT' => $_ENV['DB_PORT'] ?? '3306',
            'DB_NAME' => $_ENV['DB_NAME'] ?? 'auth_demo',
            'DB_USER' => $_ENV['DB_USER'] ?? 'root',
            'DB_PASS' => $_ENV['DB_PASS'] ?? '',
            
            'JWT_ISS' => $_ENV['JWT_ISS'] ?? 'http://localhost:8080',
            'JWT_AUD' => $_ENV['JWT_AUD'] ?? 'http://localhost:8080',
            'JWT_TTL' => (int)($_ENV['JWT_TTL'] ?? 900),
            'REFRESH_TTL_DAYS' => (int)($_ENV['REFRESH_TTL_DAYS'] ?? 30),
            'KEYS_DIR' => __DIR__ . '/../keys',
            'CURRENT_KID' => $_ENV['CURRENT_KID'] ?? 'kid1',
            
            'COOKIE_PATH' => '/',
            'COOKIE_SAMESITE' => $_ENV['COOKIE_SAMESITE'] ?? 'Lax',
            'COOKIE_SECURE' => ($_ENV['COOKIE_SECURE'] ?? '0') === '1',
        ];
    }

    public static function get(string $key) {
        self::load();
        return self::$config[$key] ?? null;
    }
}