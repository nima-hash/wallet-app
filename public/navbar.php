<!-- Navbar -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="index.php">MyWebsite</a>

    <!-- Mobile Toggle -->
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavDropdown">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navbarNavDropdown">
      <ul class="navbar-nav ms-auto" id="navbar-links">
        <!-- JS will inject login/signup OR user menu here -->
      </ul>
    </div>
  </div>
</nav>

<!-- Page content padding so navbar doesn’t overlap -->
<div style="margin-top: 80px;"></div>

<script>

// document.addEventListener('DOMContentLoaded', async function () {
const loadNavbar = async() => {
   console.log('loading navbar') 
  // Example: check localStorage for access token
  const token = window.localStorage.getItem("access_token");
  const navbarLinks = document.getElementById("navbar-links");

  // Base links (always visible)
  const baseLinks = `
    <li class="nav-item"><a class="nav-link" href="index.php">Home</a></li>
    <li class="nav-item"><a class="nav-link" href="about.php">About</a></li>
    <li class="nav-item"><a class="nav-link" href="contact.php">Contact</a></li>
  `;
  console.log(token ?? 'no acces token found');
  if (token) {
    // Example: fetch profile info with token
    const userData = await getUser();
    if (userData) {
      console.log(userData)
    const user = userData.user;
    const userRole = userData.scope;
    console.log(user);

      navbarLinks.innerHTML = baseLinks + `
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
            ${user.username || "User"}
          </a>
          <ul class="dropdown-menu dropdown-menu-end">
            <li><a class="dropdown-item" href="profile.php">Profile</a></li>
            <li><a class="dropdown-item" href="settings.php">Settings</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item text-danger" href="#" onclick="logout()">Logout</a></li>
          </ul>
        </li>
      `;
    }else{
      window.localStorage.removeItem("access_token");
      const authLinks = `
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
            Account
          </a>
          <ul class="dropdown-menu dropdown-menu-end">
            <li><a class="dropdown-item" href="login.php">Login</a></li>
            <li><a class="dropdown-item" href="signup.php">Sign Up</a></li>
          </ul>
        </li>
      `;
      navbarLinks.innerHTML = baseLinks + authLinks;
    }
    
  } else {
    console.log('you are not logged in')
    // Not logged in
    const authLinks = `
      <li class="nav-item dropdown">
        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
          Account
        </a>
        <ul class="dropdown-menu dropdown-menu-end">
          <li><a class="dropdown-item" href="login.php">Login</a></li>
          <li><a class="dropdown-item" href="signup.php">Sign Up</a></li>
        </ul>
      </li>
    `;
    navbarLinks.innerHTML = baseLinks + authLinks;
  }
}
  
  
// })
</script>
