<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resend Confirmation Email</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style/auth.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">
<?php require_once __DIR__ . '/navbar.php'?>    
<div class="container text-center">
        <div class="card shadow p-4 rounded-3">
            <div class="card-body">
                <h1 class="card-title h3 mb-3">Resend Confirmation Link</h1>
                <p class="card-text text-muted mb-4">Please enter your email address to receive a new confirmation link.</p>
                
                <div id="general-message" class="mt-3"></div>

                <form id="resend-form" class="mt-4">
                    <div class="mb-3">
                        <label for="emailInput" class="form-label visually-hidden">Email address</label>
                        <input type="email" class="form-control" id="emailInput" placeholder="Enter your email" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        Resend Link
                    </button>
                </form>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script type="text/javascript" src="JS/auth.js"></script>
</body>
</html>
