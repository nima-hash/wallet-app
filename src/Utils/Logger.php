<?php
namespace App\Utils;

use Monolog\Logger as MonologLogger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

class Logger {
    private static ?MonologLogger $logger = null;

    public static function getInstance(): MonologLogger {
        if (self::$logger === null) {
            $logFile = __DIR__ . '/../../logs/app.log';
            $handler = new StreamHandler($logFile, MonologLogger::INFO);
            
            // The format will be: [%datetime%] %level_name%: %message% %context% %extra%
            $formatter = new LineFormatter(
                "[%datetime%] %level_name%: %message% %context% %extra%\n",
                "Y-m-d H:i:s",
                false,
                true
            );
            $handler->setFormatter($formatter);

            self::$logger = new MonologLogger('app');
            self::$logger->pushHandler($handler);
        }

        return self::$logger;
    }
}