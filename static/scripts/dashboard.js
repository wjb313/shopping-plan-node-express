// navigation
const dmpLink = document.querySelector("[data-js-nav-to-dinner]");
console.log("dmp" + dmpLink);
const sliLink = document.querySelector("[data-js-nav-to-shopping-list]");
console.log("sli" + sliLink);

dmpLink.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/dinnerplan";
});

sliLink.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/shoppinglist";
});
