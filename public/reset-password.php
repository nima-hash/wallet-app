<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - Auth Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style/auth.css">
</head>

<body class="bg-light d-flex align-items-center justify-content-center vh-100">
    <?php require_once __DIR__ . '/navbar.php'?>
    <div class="container py-5">
        <div id="general-message"></div>
        <div class="row">
            <div class="col-md-6 offset-md-3">
                <h1 class="mb-4 text-center">Set Your New Password</h1>
                <div class="card p-4 shadow">
                    <form id="reset_pass_form" method="post">
                        <div class="mb-3">
                            <label for="new_pass" class="form-label">New Password</label>
                            <input id="new_pass" class="form-control" placeholder="New Password" type="password" required autocomplete="new-password">
                            <ul id="password-requirements" class="mt-2 ps-3 small">
                                <li id="req-length" class="requirement">Minimum length: 8 characters</li>
                                <li id="req-number" class="requirement">At least 1 number</li>
                                <li id="req-special" class="requirement">At least 1 special character (!@#$%^&*)</li>
                                <li id="req-uppercase" class="requirement">At least 1 uppercase letter</li>
                                <li id="req-lowercase" class="requirement">At least 1 lowercase letter</li>
                            </ul>
                        </div>
                        <div class="mb-3">
                            <label for="new_pass_confirm" class="form-label">Confirm New Password</label>
                            <input id="new_pass_confirm" class="form-control" placeholder="Confirm New Password" type="password" required autocomplete="new-password">
                            <div id="confirm_pass_err" class="form-error"></div>
                        </div>
                        <div class="d-grid gap-2">
                            <button id="btn_reset_pass" type="submit" class="btn btn-primary">Reset Password</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script type="text/javascript" src="JS/auth.js"></script>
</body>
</html>
