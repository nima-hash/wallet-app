<?php
require_once __DIR__ . '/../vendor/autoload.php';
 
use App\Config;
use App\Utils\Cors;
use App\Database;
use App\Routes;

// Load configuration
Config::load();

// Enable CORS
Cors::handle();

// Initialize database connection
$db = new Database();

// Handle the request
$router = new Routes();

$router->handleRequest();