<?php

use Doctrine\DBAL\DriverManager;
use Doctrine\Migrations\DependencyFactory;
use Doctrine\Migrations\Configuration\Migration\ConfigurationArray;
use Doctrine\Migrations\Configuration\Connection\ExistingConnection;

require_once __DIR__ . '/vendor/autoload.php';

// Load .env variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Create DBAL connection
$connection = DriverManager::getConnection([
    'dbname'   => $_ENV['DB_NAME'],
    'user'     => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASS'],
    'host'     => $_ENV['DB_HOST'],
    'port'     => $_ENV['DB_PORT'],
    'driver'   => 'pdo_mysql',
    'charset'  => 'utf8mb4',
]);

// Return DependencyFactory for the command-line tool
return DependencyFactory::fromConnection(
    new ConfigurationArray([
        'migrations_paths' => [
            'App\Migrations' => __DIR__ . '/migrations',
        ],
        'all_or_nothing' => true,
        'check_database_platform' => true,
    ]),
    new ExistingConnection($connection)
);
