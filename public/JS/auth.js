const API = window.location.origin;
let accessTokens = null;

// Function to handle API requests with modern practices
// async function req(path, opts = {}) {
//   // Ensure headers are present
//   opts.headers = opts.headers || {};
//   // Set default content-type for POST/PUT requests if not specified
//   if (opts.method && opts.method !== 'GET' && !opts.headers['Content-Type']) {
//     opts.headers['Content-Type'] = 'application/json';
//   }

//   // Get access token from local storage
//   const accessToken = localStorage.getItem('access_token');
//   // Add Authorization header if authentication is required and token exists
//   console.log(accessToken);
//   if (opts.auth && accessToken) {
//     opts.headers['Authorization'] = 'Bearer ' + accessToken;
//   }
//   let res;
//   try {
//     res = await fetch(API + path, opts);

//     if (res.status === 204) {
//       return { status: 204, ok: res.ok, body: "No Content" }; 
//     }
//     // Read the response body ONCE, but only if the response has content
//     let body = {};
//     try {
//       body = await res.json();
//     } catch (e) {
//       throw new Error ("Failed to parse JSON: " + e.message);
//     }
//     console.log(body);
//     // Handle 401 Unauthorized errors by trying to refresh the token
//     if (res.status === 401 && opts.auth && !path.includes('/refresh')) {
//       if (body.error === 'token_revoked') {
          
//           // You might want to clear local storage here to ensure no lingering tokens.
//           localStorage.removeItem('access_token');
//           // Redirect to login page
//           window.location.href = 'login.php';
//           showMessage(generalMessage, 'Yous session is outdated. Please log in again.')
//           return; // Exit the function
//       } else {
//         // For all other 401 errors, attempt to refresh.
//         const refreshSuccess = await refreshToken();
//         if (refreshSuccess) {
//           return req(path, opts);
//         }
//       }
//     }

//     // Handle token management after a successful login or refresh
//     if (res.ok && (path.includes('/login') || path.includes('/refresh'))) {
//       if (body.access_token) {
//         localStorage.setItem('access_token', body.access_token);
//         // Refresh token is handled by the server as an HTTP-only cookie
//       }
//     }

//     if (!res.ok) {
//         throw new Error(body.error ?? 'Something went wrong');
//     }

//     // Return a structured response object
//     return { status: res.status, ok: res.ok, body: body?.message || body };
//   } catch (error) {
//     console.error("API Request Failed:", error);
//     return { status: res.status, ok: res.ok, body: { 'error': error.message } };
//   }
// }

// A simple function to show messages, for demonstration
function showMessage(element, message, type) {
    const p = document.createElement('p');
    p.innerText = message;
    p.className = 'alert alert-' + type; // Using Bootstrap classes for example
    element.appendChild(p);
}

// Updated req function with centralized error handling
async function req(path, opts = {}, retry = 0) {
    opts.headers = opts.headers || {};
    if (opts.method && opts.method !== 'GET' && !opts.headers['Content-Type']) {
        opts.headers['Content-Type'] = 'application/json';
    }

    const accessToken = localStorage.getItem('access_token');
    if (opts.auth && accessToken) {
        opts.headers['Authorization'] = 'Bearer ' + accessToken;
    }

    let res;
    try {
        res = await fetch(API + path, opts);
        let body = {};
        if (res.status !== 204) {
            body = await res.json();
        }
        console.log(body);
        // Handle authentication errors centrally
        if (res.status === 401 && opts.auth) {
            if (body.error === 'token_revoked' || body.error === 'invalid_token') {
                // Token is permanently invalid, no retry possible.
                localStorage.removeItem('access_token');
                window.location.href = 'login.php';
                // Return an error to stop execution
                throw new Error("Session invalid. Please log in again.");
            } else if (body.error === 'Expired token' && retry < 1) {
                // Token is just expired. Attempt to refresh once.
                const refreshSuccess = await refreshAccessToken();
                console.log(refreshSuccess);
                if (refreshSuccess) {
                    // Retry the original request recursively
                    return req(path, opts, 1);
                }
            }
        }

        // If the response is not ok and an error was not handled above, throw it
        if (!res.ok) {
            throw new Error(body.error ?? 'Something went wrong');
        }

        return { status: res.status, ok: res.ok, body: body?.message || body };

    } catch (error) {
        console.error("API Request Failed:", error);
        throw error;
    }
}

// Function to automatically refresh the access token
async function refreshAccessToken() {
  const r = await req('/api/refresh', {
    method: 'POST',
  });
  if(r.ok) {
    window.localStorage.setItem('access_token', r.body.access_token);
  }
  return r.ok;
}

const checkPasswordValidity = () => {
    // Existing password validation logic
    const passwordInput = document.getElementById('new_pass');
    if(!passwordInput) return;
    const reqLength = document.getElementById('req-length');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');
    const reqUppercase = document.getElementById('req-uppercase');
    const reqLowercase = document.getElementById('req-lowercase');

    passwordInput.addEventListener('input', () => {
        const value = passwordInput.value;
        const hasLength = value.length >= 8;
        const hasNumber = /[0-9]/.test(value);
        const hasSpecial = /[!@#$%^&*]/.test(value);
        const hasUppercase = /[A-Z]/.test(value);
        const hasLowercase = /[a-z]/.test(value);

        reqLength.style.color = hasLength ? 'green' : 'red';
        reqNumber.style.color = hasNumber ? 'green' : 'red';
        reqSpecial.style.color = hasSpecial ? 'green' : 'red';
        reqUppercase.style.color = hasUppercase ? 'green' : 'red';
        reqLowercase.style.color = hasLowercase ? 'green' : 'red';

        if (hasLength && hasNumber && hasSpecial && hasUppercase && hasLowercase) {
            passwordInput.setCustomValidity('');
        } else {
            passwordInput.setCustomValidity('Password does not meet requirements');
        }
    });
};

const validateUsername = () => {
    // Existing username validation logic
    const usernameInput = document.getElementById('reg_username');
    const usernameErr = document.getElementById('username_err');

    if(!usernameInput || !usernameErr) return;

    usernameInput.addEventListener('input', () => {
        if(usernameInput.value.length < 3) {
            usernameErr.innerText = 'Username must be at least 3 characters long!';
        }else {
            usernameErr.innerText = '';
        }
    });

};

const validateEmail = () => {
    const emailInput = document.getElementById('reg_email');
    const emailErr = document.getElementById('email_err');
    if(!emailInput || !emailErr) return;
    emailInput.addEventListener("input", () => {
        emailErr.innerHTML = '';
    })

    emailInput.addEventListener("blur", () => {
        const regex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
        if(!regex.test(emailInput.value)) {
            emailErr.innerText ='Please enter a valid email!';
        }
    })

};

// Function to display messages on the page
function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `alert mt-3 alert-${type}`;
}

// Function to handle registration form submission
function handleRegister() {
  const regForm = document.getElementById('reg_form');
  const generalMessage = document.getElementById('general-message');

  regForm.addEventListener('submit', async function(event) {
    event.preventDefault();

    const username = document.getElementById('reg_username').value.trim();
    const email = document.getElementById('reg_email').value.trim();
    const password = document.getElementById('reg_pass').value;
    const confirmPassword = document.getElementById('reg_pass_confirm').value;

    if (password !== confirmPassword) {
      showMessage(generalMessage, 'Passwords do not match.', 'danger');
      return;
    }

    const response = await req('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        username: username,
        email: email,
        password: password
      })
    });
    
    if (response.ok) {
      showMessage(generalMessage, 'Registration successful! Please log in.', 'success');
      window.location.href = 'login.php';
    } else {
      showMessage(generalMessage, `Registration failed: ${response.body.error}`, 'danger');
    }
  });
}

// Function to handle login form submission
function handleLogin() {
  const logForm = document.getElementById('log_form');
  const generalMessage = document.getElementById('general-message');

  logForm.addEventListener('submit', async function(event) {
    event.preventDefault();

    const email = document.getElementById('log_email').value.trim();
    const password = document.getElementById('log_pass').value;

    const r = await req('/api/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    console.log(r);
    if (r.ok) {
      window.localStorage.setItem('access_token', r.body.access_token);
      window.location.href = 'dashboard.php';
    } else if (r.body.error.includes('email not yet verified')){
      window.location.href = 'resend-confirmation.html';
    }else {
      showMessage(generalMessage, `Login failed: ${r.body.error}`, 'danger');
    }
  });
}

function handleForgotPassword() {
    const forgotPassForm = document.getElementById('forgot_pass_form');
    const generalMessage = document.getElementById('general-message');

    forgotPassForm.addEventListener('submit', async function(event) {
        event.preventDefault();

        const email = document.getElementById('forgot_email').value.trim();

        const response = await req('/api/password/forgot', {
            method: 'POST',
            body: JSON.stringify({ email: email })
        });
        
        if (response.ok) {
            showMessage(generalMessage, 'If an account with that email exists, a password reset link has been sent.', 'success');
        } else {
            showMessage(generalMessage, `An error occurred: ${response.body}`, 'danger');
        }
    });
}
// Client-side validation for the signup form
function signupFormValidation() {
    const usernameInput = document.getElementById('reg_username');
    const usernameErr = document.getElementById('username_err');
    const emailInput = document.getElementById('reg_email');
    const emailErr = document.getElementById('email_err');
    const passwordInput = document.getElementById('reg_pass');
    const confirmPasswordInput = document.getElementById('reg_pass_confirm');
    const confirmPassErr = document.getElementById('confirm_pass_err');

    // Password requirements display
    const requirements = {
        length: document.getElementById("req-length"),
        number: document.getElementById("req-number"),
        special: document.getElementById("req-special"),
        uppercase: document.getElementById("req-uppercase"),
        lowercase: document.getElementById("req-lowercase"),
    };
    const checks = {
        length: (pw) => pw.length >= 8,
        number: (pw) => /\d/.test(pw),
        special: (pw) => /[!@#$%^&*]/.test(pw),
        uppercase: (pw) => /[A-Z]/.test(pw),
        lowercase: (pw) => /[a-z]/.test(pw),
    };
    passwordInput.addEventListener("input", () => {
        const pw = passwordInput.value;
        for (let key in checks) {
            if (checks[key](pw)) {
                requirements[key].classList.remove("invalid");
                requirements[key].classList.add("valid");
            } else {
                requirements[key].classList.remove("valid");
                requirements[key].classList.add("invalid");
            }
        }
    });

    // Username validation on blur
    usernameInput.addEventListener("blur", () => {
        if (usernameInput.value.length < 3) {
            usernameErr.innerText = 'Username must be at least 3 characters.';
        } else {
            usernameErr.innerText = '';
        }
    });

    // Email validation on blur
    emailInput.addEventListener("blur", () => {
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!regex.test(emailInput.value)) {
            emailErr.innerText = 'Please enter a valid email!';
        } else {
            emailErr.innerText = '';
        }
    });
    
    // Password confirmation on blur
    confirmPasswordInput.addEventListener("blur", () => {
        if (confirmPasswordInput.value !== passwordInput.value) {
            confirmPassErr.innerText = 'Both Password fields must match.';
        } else {
            confirmPassErr.innerText = '';
        }
    });
}

const handleResendConfirmation = () => {
    const resendForm = document.getElementById('resend-form');
    if (!resendForm) return;

    resendForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = document.getElementById('emailInput').value;
        

        try {
            const response = await req('/api/resend-confirmation-email', {
                method: 'POST',
                body: JSON.stringify({ email: email })
            });

            if (r.ok) {
              window.location.href = 'dashboard.php';
            } else if (r.body.error.includes('email not yet verified')){
              window.location.href = 'resend-confirmation.html';
            }else {
              showMessage(generalMessage, `Login failed: ${r.body.error}`, 'danger');
            }
            if (response.ok) {
                window.location.href = 'login.php';
                showMessage(generalMessage, 'If an account exists, a new confirmation link has been sent.', 'success');                
            } else {
                showMessage(generalMessage, response?.error ?? 'Failed to send confirmation link. Please try again.', 'danger');
            }
        } catch (error) {
            console.error('Error:', error);
            showMessage(generalMessage, error.message ?? 'Failed to send confirmation link. Please try again.', 'danger');
        }
    });
};

const logout = async () => {
    try {
        const r = await req('/api/logout', { method: 'POST', auth: true });
        if (r.status === 204 || r.body == 'You have successfully logged out') {
            localStorage.removeItem('access_token');
            window.location.href = 'login.php';
        }
    } catch (error) {
        console.error('Logout failed:', error);
        // Even on error, we might want to log out the user
        localStorage.removeItem('access_token');
        window.location.href = 'login.php';
    }
}
// const googleLogin = () => {
    // const response = await req('/api/login/google', {
    //   method: 'GET'
    // })
    // console.log(response);
    // if(!response.ok){
    //   showMessage(generalMessage, response.body.error ?? 'invalid response', 'danger');
    //   return;
    // }
    // if(!response.body.access_token || !response.body.expires_in){
    //   showMessage(generalMessage, 'invalid response', 'danger');
    //   return;
    // }
    // window.localStorage.setItem('access_token', response.body.access_token);
//     window.location.href = '/api/login/google';
// }

const getUser = async () => {
    try {
        const r = await req('/api/me', { method: 'GET', auth: true });
        
        // Assuming req handles all 401 redirects, a successful response means a valid user
        if (r.ok && r.body && r.body.user) {
            return r.body;
        } else {
            // Should not happen with the improved req method, but as a fallback
            console.error("Authentication failed on load.");
            window.location.href = 'login.php';
        }
    } catch (error) {
        console.error("Dashboard load failed:", error);
        window.location.href = 'login.php';
    }
};

// Core function to load and authenticate the dashboard
const loadDashboard = async () => {
    try {
      const user = await getUser();
      if (user) {
        console.log(user)
        displayUserInfo(user);          
      } else {
            console.error("Could not get user");
            window.location.href = 'login.php';
        }
    } catch (error) {
        console.error("Dashboard load failed:", error);
    }
};

// Function to update the UI with user info
const displayUserInfo = (userData) => {
  const userInfoDiv = document.getElementById('user-info');
  const welcomeMessage = document.getElementById('welcome-message');
  const user = userData.user
  const userRole = userData.scope
    if (user) {
        welcomeMessage.textContent = `Welcome, ${user.email}!`;
        userInfoDiv.innerHTML = `
            <p><strong>ID:</strong> ${user.id}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Joined:</strong> ${new Date(user.created_at).toLocaleDateString()}</p>
            <p><strong>Scope:</strong> ${userRole}</p>
        `;
    }
};

const handleDashboard = async () => {
    //Check for access token
    const fragment = new URLSearchParams(window.location.hash.substring(1));
    const accessToken = fragment.get('access_token');
    
    if (accessToken) {
        window.localStorage.setItem('access_token', accessToken);
        // Clear the fragment from the URL bar for security
        window.history.replaceState({}, document.title, window.location.pathname);
    }


    // DOM Elements
    
    const btnMe = document.getElementById('btn_me');
    const btnLogout = document.getElementById('btn_logout');

    

    


    
    // Set up the event listeners
    if (btnMe) {
        btnMe.addEventListener('click', async () => {
            // The logic to get user info is already in loadDashboard
            // This button now simply reloads the user info
            await loadDashboard(); 
        });
    }

    if (btnLogout) {
        btnLogout.addEventListener('click', async () => {
          await logout()
        });
        
    }
    
    // Initial call to load the dashboard on page load
    loadDashboard();
};

const handlePasswordReset = () => {
    const resetForm = document.getElementById('reset_pass_form');
    if (!resetForm) return;

    // Password validation on input
    const newPassInput = document.getElementById('new_pass');
    const reqLength = document.getElementById('req-length');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');
    const reqUppercase = document.getElementById('req-uppercase');
    const reqLowercase = document.getElementById('req-lowercase');

    if (newPassInput) {
        newPassInput.addEventListener('input', () => {
            const value = newPassInput.value;
            reqLength.style.color = (value.length >= 8) ? 'green' : 'red';
            reqNumber.style.color = (/[0-9]/.test(value)) ? 'green' : 'red';
            reqSpecial.style.color = (/[!@#$%^&*]/.test(value)) ? 'green' : 'red';
            reqUppercase.style.color = (/[A-Z]/.test(value)) ? 'green' : 'red';
            reqLowercase.style.color = (/[a-z]/.test(value)) ? 'green' : 'red';
        });
    }

    resetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        const newPass = document.getElementById('new_pass').value;
        const confirmPass = document.getElementById('new_pass_confirm').value;
        const confirmPassErr = document.getElementById('confirm_pass_err');

        if (!token) {
            showMessage(GeneralMessage, 'Invalid or missing password reset token.', 'danger');
            return;
        }

        if (newPass !== confirmPass) {
            confirmPassErr.innerText = 'Passwords do not match!';
            return;
        } else {
            confirmPassErr.innerText = '';
        }

        const body = JSON.stringify({ token: token, password: newPass });

        try {
            const r = await req('/api/password/reset', { method: 'POST', body: body });
            if (r) {
                showMessage(GeneralMessage, 'Your password has been reset successfully! You can now log in.', 'success');
                // Wait for a few seconds before redirecting
                setTimeout(() => {
                    window.location.href = 'login.php';
                }, 3000);
            }
        } catch (error) {
            console.error('Password reset failed:', error);
            showMessage(GeneralMessage, error.message, 'danger');
        }
    });
};

// Initialize the correct script based on the current page
document.addEventListener('DOMContentLoaded', async () => {
  if (window.location.pathname.includes('signup.php')) {
    signupFormValidation();
    handleRegister();
  }
  if (window.location.pathname.includes('login.php')) {
    handleLogin();
  }
  if (window.location.pathname.includes('forgot-password.html')) {
    handleForgotPassword();
  }
  if (window.location.pathname.includes('dashboard.php')) {
    handleDashboard();
  }
  if (window.location.pathname.includes('reset-password')) {
    handlePasswordReset();
  }
  if (window.location.pathname.includes('resend-confirmation')) {
    handleResendConfirmation();
  }

  await loadNavbar();
});