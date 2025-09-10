<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>Forgot Password</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style/auth.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">
<?php require_once __DIR__ . '/navbar.php'?>
<div class="container py-5">
    <div id="general-message"></div>
    <div class="row">
        <div class="col-md-6 offset-md-3">
            <h1 class="mb-4 text-center">Reset Your Password</h1>
            <div class="card p-4 shadow">
                <form id="forgot_pass_form" method="post">
                    <div class="mb-3">
                        <label for="forgot_email" class="form-label">Email address</label>
                        <input id="forgot_email" class="form-control" placeholder="Enter your email" type="email" required>
                    </div>
                    <div class="d-grid gap-2">
                        <button id="btn_forgot_pass" type="submit" class="btn btn-primary">Send Reset Link</button>
                    </div>
                </form>
                <div class="mt-3 text-center">
                    <a href="login.php">Back to Login</a>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="js/auth.js"></script>
</body>
</html>