<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Dashboard - Auth Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="style/auth.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">
<?php require_once __DIR__ . '/navbar.php'?>
<div class="container py-5">
  <div id="general-message" ></div>
  <div class="row">
    <div class="col-md-6 offset-md-3">
      <h1 class="mb-4 text-center">Dashboard</h1>
      <div class="card p-4 shadow">
        <h2 id="welcome-message" class="text-center mb-3">Welcome, User!</h2>
        <div id="user-info" class="mb-3">
          <p>Click "Get My Info" to see your details.</p>
        </div>
        <div class="d-grid gap-2">
          <button id="btn_me" class="btn btn-primary">Get My Info</button>
          <button id="btn_logout" class="btn btn-danger">Log Out</button>
        </div>
      </div>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script type="text/javascript" src="JS/auth.js"></script>
</body>
</html>
