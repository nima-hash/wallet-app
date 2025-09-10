<?php
namespace App;

use PDO;
use Exception;
use App\Config;
use App\Utils\Logger;
use Monolog\Logger as MonologLogger;

class Database {
    private static ?PDO $pdo = null;

    public function __construct() {
        if (!self::$pdo) {
            $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', Config::get('DB_HOST'), Config::get('DB_PORT'), Config::get('DB_NAME'));
            try {
                self::$pdo = new PDO($dsn, Config::get('DB_USER'), Config::get('DB_PASS'), [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]);
                Logger::getInstance()->info('Database connection established successfully.');
            } catch (Exception $e) {
                Logger::getInstance()->critical('Database connection failed.', ['error_message' => $e->getMessage()]);
                die('Database connection failed: ' . $e->getMessage());
            }
        }
    }

    public function getPdo(): PDO {
        return self::$pdo;
    }
}
