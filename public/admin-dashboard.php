<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="style/basic.css">
</head>
<body class="bg-light">
<?php require_once __DIR__ . '/navbar.php'?>

<div class="container py-5">
  <div class="row">
    <div class="col-md-8 offset-md-2">
      <div class="card p-4 shadow-sm">
        <h2 class="mb-4 text-center">Admin Dashboard</h2>
        <div id="admin-content">
          <p class="lead text-center">Loading admin content...</p>
        </div>
        <div id="error-message" class="alert alert-danger" style="display: none;"></div>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script type="text/javascript" src="https://cdn.jsdelivr.net/npm/js-cookie@3.0.5/dist/js.cookie.min.js"></script>
<script type="module" src="auth.js"></script>
<script>
  // Script to check user role and load admin content
  document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('access_token');
    const adminContent = document.getElementById('admin-content');
    const errorMessage = document.getElementById('error-message');

    if (!token) {
      errorMessage.textContent = 'You must be logged in to view this page.';
      errorMessage.style.display = 'block';
      setTimeout(() => window.location.href = 'login.php', 3000);
      return;
    }

    try {
      const response = await fetch('/api/me', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await response.json();
      
      if (response.ok && data.scope === 'admin') {
        // User is an admin, load content
        adminContent.innerHTML = `
          <p>Welcome, Administrator!</p>
          <p>This is content that only users with the 'admin' scope can see.</p>
          <p>This demonstrates a successful client-side and server-side role-based access control.</p>
        `;
      } else {
        // User is not an admin, show an error and redirect
        errorMessage.textContent = 'Access Denied: You do not have permission to view this page.';
        errorMessage.style.display = 'block';
        setTimeout(() => window.location.href = 'dashboard.html', 3000);
      }
    } catch (error) {
      errorMessage.textContent = 'An error occurred. Please try again.';
      errorMessage.style.display = 'block';
      console.error('Error fetching user data:', error);
    }
  });
</script>
</body>
</html>
