<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Confirmed</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <?php require_once __DIR__ . '/navbar.php'?>
    <div class="max-w-md w-full bg-white p-8 rounded-lg shadow-lg text-center">
        <div class="flex justify-center mb-4">
            <svg class="w-20 h-20 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
        </div>
        <h1 class="text-3xl font-bold text-gray-800 mb-4">Success!</h1>
        <p class="text-gray-600 mb-6">If an account exists, a new confirmation link has been sent.</p>
        <a href="/login.php" class="inline-block bg-indigo-600 text-white font-semibold py-2 px-6 rounded-full hover:bg-indigo-700 transition-colors">
            Go to Login
        </a>
    </div>
</body>
</html>