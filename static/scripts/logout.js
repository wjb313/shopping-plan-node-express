// navigation
const dashLink = document.querySelector("[data-js-nav-to-dashboard]");
const loggedOut = document.querySelector("[data-js-nav-to-logged-out]");

dashLink.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/dashboard";
});

loggedOut.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/loggedOut";
});
