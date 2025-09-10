<?php
namespace App\Services;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Dotenv\Dotenv;
use App\Utils\Logger;


class Mailer {
    private PHPMailer $mailer;

    public function __construct() {
        // Load .env variables if not already loaded
        if (!isset($_ENV['MAIL_HOST'])) {
            $dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
            $dotenv->load();
        }

        $this->mailer = new PHPMailer(true);
        $this->mailer->isSMTP();
        $this->mailer->Host       = $_ENV['MAIL_HOST'];
        $this->mailer->SMTPAuth   = true;
        $this->mailer->Username   = $_ENV['MAIL_USERNAME'];
        $this->mailer->Password   = $_ENV['MAIL_PASSWORD'];
        $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $this->mailer->Port       = $_ENV['MAIL_PORT'];
        Logger::getInstance()->info('Mailer service initialized successfully.');
    }

    public function sendEmail(string $to, string $subject, string $body) {
        try {
            $this->mailer->addAddress($to);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = $subject;
            $this->mailer->Body    = $body;
            $this->mailer->AltBody = strip_tags($body);
            $this->mailer->send();
            Logger::getInstance()->info('Email sent successfully.', ['recipient' => $to, 'subject' => $subject]);
            return true;
        } catch (Exception $e) {
            Logger::getInstance()->error('Failed to send email.', ['recipient' => $to, 'subject' => $subject, 'error_message' => $this->mailer->ErrorInfo]);
            return $e->getMessage();
        }
    }

    public function sendEmailConfirmation(string $toEmail, string $token, int $userId) :array{
        $subject = 'Please confirm your email address';
        // Construct the confirmation link
        $confirmationUrl = sprintf(
            'http://localhost:8000/confirm-email?token=%s&user_id=%d',
            urlencode($token),
            $userId
        );

        $fromEmail = $_ENV['MAIL_FROM_EMAIL'] ?? $_ENV['MAIL_USERNAME'];
        $fromName = $_ENV['MAIL_FROM_NAME'] ?? 'Auth Demo';

        $htmlBody = sprintf(
            '<p>Hello,</p><p>Thank you for registering with us. Please click the link below to confirm your email address:</p><p><a href="%s">Confirm My Email</a></p><p>If you did not sign up for this account, you can safely ignore this email.</p><p>Thank you,<br>%s</p>',
            htmlspecialchars($confirmationUrl),
            htmlspecialchars($fromName)
        );

        Logger::getInstance()->info('Preparing to send email confirmation.', ['recipient' => $toEmail, 'user_id' => $userId]);

        try {
            $this->mailer->setFrom($fromEmail, $fromName);
            $this->mailer->addAddress($toEmail);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = $subject;
            $this->mailer->Body = $htmlBody;
            $this->mailer->AltBody = strip_tags($htmlBody);
            $this->mailer->send();
            Logger::getInstance()->info('Email confirmation sent successfully.', ['recipient' => $toEmail, 'user_id' => $userId]);
            return ['success' => true, 'message' => "The confirmation was successfully sent to $toEmail"];
        } catch (Exception $e) {
            Logger::getInstance()->error('Failed to send email confirmation.', ['recipient' => $toEmail, 'user_id' => $userId, 'error_message' => $this->mailer->ErrorInfo]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
}
