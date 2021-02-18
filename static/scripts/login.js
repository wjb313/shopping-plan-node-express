// navigation
const login = document.querySelector("[data-js-nav-to-login]");

login.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/";
});
