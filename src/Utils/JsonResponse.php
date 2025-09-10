<?php
namespace App\Utils;

use App\Utils\Logger;

class JsonResponse {
    public static function send($data, int $status = 200) {
        // Log the response data and status before sending
        Logger::getInstance()->info('Sending JSON response.', ['status' => $status, 'data' => $data]);
        
        http_response_code($status);
        header('Content-Type: application/json');
        if ($data !== null) {
            echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        exit;
    }
}
