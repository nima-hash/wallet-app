<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirmation Failed</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 500px;
        }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center vh-100">
    <?php require_once __DIR__ . '/navbar.php'?>
    <div class="container text-center">
        <div class="card shadow p-4 rounded-3">
            <div class="card-body">
                <svg class="mb-4" xmlns="http://www.w3.org/2000/svg" width="80" height="80" fill="#dc3545" class="bi bi-x-circle" viewBox="0 0 16 16">
                    <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                    <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708"/>
                </svg>
                <h1 class="card-title h3 mb-3">Confirmation Failed</h1>
                <p class="card-text text-muted mb-4">We were unable to confirm your email address. This may be due to an invalid or expired link.</p>
                
                <!-- Resend Form -->
                <form id="resend-form" class="mt-4">
                    <div class="mb-3">
                        <label for="emailInput" class="form-label visually-hidden">Email address</label>
                        <input type="email" class="form-control" id="emailInput" placeholder="Enter your email" required>
                    </div>
                    <button type="submit" class="btn btn-danger w-100">
                        Resend Confirmation Link
                    </button>
                </form>
                <div id="resend-message" class="mt-3 text-success d-none">Link resent successfully!</div>
                <div id="error-message" class="mt-3 text-danger d-none">Failed to resend link. Please try again.</div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('resend-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = document.getElementById('emailInput').value;
            const resendMessage = document.getElementById('resend-message');
            const errorMessage = document.getElementById('error-message');
            
            resendMessage.classList.add('d-none');
            errorMessage.classList.add('d-none');

            try {
                const response = await fetch('/api/resend-confirmation-email', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email: email })
                });

                if (response.ok) {
                    resendMessage.classList.remove('d-none');
                } else {
                    errorMessage.classList.remove('d-none');
                }
            } catch (error) {
                console.error('Error:', error);
                errorMessage.classList.remove('d-none');
            }
        });
    </script>
</body>
</html>
