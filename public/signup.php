<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign Up - Auth Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="style/auth.css">
  <link rel="stylesheet" href="style/basic.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100 flex-column">
<?php require_once __DIR__ . '/navbar.php'?>
<div class="container py-5">
    <div id="general-message" ></div>
  <div class="row">
    <div class="col-md-6 offset-md-3">
      <h1 class="mb-4 text-center">Create an Account</h1>
      <div class="card p-4 shadow">
        <form method="post" id="reg_form">
          <div class="mb-3">
            <label for="reg_username" class="form-label">Username</label>
            <input id="reg_username" class="form-control" placeholder="Username" name="reg_username" required  autocomplete="username" >
            <div id="username_err" class="form-error"></div>
          </div>
          <div class="mb-3">
            <label for="reg_email" class="form-label">Email address</label>
            <input id="reg_email" class="form-control" placeholder="Email" name="reg_email" type="email" required autocomplete="email">
            <div id="email_err" class="form-error"></div>
          </div>
          <div class="mb-3">
            <label for="reg_pass" class="form-label">Password</label>
            <input id="reg_pass" class="form-control" placeholder="Password" type="password" name="reg_pass" required autocomplete="new-password">
            <ul id="password-requirements" class="mt-2 ps-3 small">
                <li id="req-length" class="requirement">Minimum length: 8 characters</li>
                <li id="req-number" class="requirement">At least 1 number</li>
                <li id="req-special" class="requirement">At least 1 special character (!@#$%^&*)</li>
                <li id="req-uppercase" class="requirement">At least 1 uppercase letter</li>
                <li id="req-lowercase" class="requirement">At least 1 lowercase letter</li>
            </ul>
          </div>
          <div class="mb-3">
            <label for="reg_pass_confirm" class="form-label">Confirm Password</label>
            <input id="reg_pass_confirm" class="form-control" placeholder="Confirm Password" type="password" required autocomplete="new-password">
            <div id="confirm_pass_err" class="form-error" ></div>

          </div>
          <div class="d-grid gap-2">
            <button id="btn_register" type="submit" class="btn btn-primary">Register</button>
          </div>
        </form>
        <div class="mt-3 text-center">
            <p class="text-center">Already have an account? <a href="login.php" >Login</a></p>
        </div>
      </div>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
<script src="js/auth.js"></script>
</body>
</html>