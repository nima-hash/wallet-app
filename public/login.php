<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Log In - Auth Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="style/auth.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">
<?php require_once __DIR__ . '/navbar.php'?>
<div class="container py-5">
      <div id="general-message" ></div>
  <div class="row">
    <div class="col-md-6 offset-md-3">
      <h1 class="mb-4 text-center">Log In to Your Account</h1>
      <div class="card p-4 shadow">
        <form id="log_form" method="post">
          <div class="mb-3">
            <label for="log_email" class="form-label">Email address</label>
            <input id="log_email" class="form-control" placeholder="Email" type="email" required autocomplete="email">
          </div>
          <div class="mb-3">
            <label for="log_pass" class="form-label">Password</label>
            <input id="log_pass" class="form-control" placeholder="Password" type="password" required autocomplete="current-password">
          </div>
          <div class="d-grid gap-2">
            <button id="btn_login" type="submit" class="btn btn-success">Login</button>
          </div>
        </form>
        <div class="mt-3 text-center">
          <a href="signup.php">Don't have an account? Sign Up</a>
          <span class="mx-2">|</span>
          <a href="forgot-password.html">Forgot Password?</a>
        </div>
        <div class="mt-4 text-center">
          <p class="text-muted">Or log in with:</p>
          <a href="/api/login/google" class="btn btn-outline-secondary d-flex align-items-center justify-content-center" style="gap: 10px;">
            <img src="https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png" alt="Google Logo" style="width: 20px; height: 20px;">
            <span class="fw-bold">Google</span>
          </a>
        </div>
      </div>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="js/auth.js"></script>
</body>
</html>
