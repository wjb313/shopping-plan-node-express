// navigation
const dmpLink = document.querySelector("[data-js-nav-to-dinner]");
const sliLink = document.querySelector("[data-js-nav-to-shopping-list]");
const dashLink = document.querySelector("[data-js-nav-to-dashboard]");
const logout = document.querySelector("[data-js-nav-to-logout]");

dmpLink.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/dinnerplan";
});

sliLink.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/shoppinglist";
});

dashLink.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/dashboard";
});

logout.addEventListener("click", (e) => {
  e.preventDefault();
  location.href = "/logout";
});

// ***MENU PLAN PAGE***
// variables/constants for manipulating the DOM
let currentEditDay;
let currentEditDayNumber;
let currentDayDisplay;

// define days of the week
let days = [
  "Saturday",
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
];

// declare empty object for dinner menu plan (dmp) content JSON file
let dmpContent = {
  day1: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
  day2: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
  day3: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
  day4: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
  day5: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
  day6: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
  day7: {
    main: "",
    side1: "",
    side2: "",
    other: "",
    notes: "",
  },
};

// *** POPULATE DAYS OF THE WEEK
// function dotwPopulate() {
//   for (let i = 0; i < days.length; i++) {
//     const dotwSpanCreate = document.createElement("span");
//     let currentDayDOM = document.querySelector(
//       '[data-js-dotw="day' + [i + 1] + '"]'
//     );
//     currentDayDOM.textContent = days[i].charAt(0);
//     dotwSpanCreate.textContent = days[i];
//     dotwSpanCreate.className = "tooltiptext";
//     currentDayDOM.appendChild(dotwSpanCreate);
//   }
// }

//dotwPopulate();

// *** LOAD DINNER MENU PLAN CONTENT INTO PAGE
// define function to load content into page, assign to proper fields
// ami = 'all menu items'
function loadMenuContent() {
  console.log("Loading...");
  let amiList = document.querySelectorAll(".allMenuItems");

  amiList.forEach((item) => {
    if (item.dataset.jsMain) {
      let currentDay = item.dataset.jsMain;
      item.textContent = dmpContent[currentDay]["main"];
    } else if (item.dataset.jsSide1) {
      let currentDay = item.dataset.jsSide1;
      item.textContent = dmpContent[currentDay]["side1"];
    } else if (item.dataset.jsSide2) {
      let currentDay = item.dataset.jsSide2;
      item.textContent = dmpContent[currentDay]["side2"];
    } else if (item.dataset.jsOther) {
      let currentDay = item.dataset.jsOther;
      item.textContent = dmpContent[currentDay]["other"];
    } else {
      let currentDay = item.dataset.jsNotesSpan;
      item.textContent = dmpContent[currentDay]["notes"];
    }
  });

  addOrEdit();
}

loadMenuContent();

// check for content and adjust add/edit text accordingly
function addOrEdit() {
  let btnText = document.querySelectorAll("[data-js-edit-menu]");
  let mainDishList = document.querySelectorAll(".mainDish");

  mainDishList.forEach(function (item, index) {
    if (item.textContent !== "") {
      btnText[index].textContent = "Edit";
    } else {
      btnText[index].textContent = "Add";
    }
  });
}

// *** EDIT MENU ITEMS AND MENU ITEM NOTES

// *** EDIT DINNER MENU PLAN ENTRIES ***
// variables/constants for DOM manipulation
const dmpModal = document.querySelector("[data-js-dmp-modal]");
const editMenu = document.querySelectorAll("[data-js-edit-menu]");
const submitMenuEdit = document.querySelector("[data-js-new-item-submit]");
const dmpModalClose = document.querySelector("[data-js-dmp-modal-close]");
const inputFields = document.querySelectorAll(".modalFormInput");
const dmpModalHeader = document.querySelector("[data-js-dmp-modal-header]");

// handle event --> button click to call open dmp edit modal function
editMenu.forEach((e) => e.addEventListener("click", openEditModal));

// define function to open modal and populate existing data where applicable
function openEditModal(e) {
  console.log(inputFields);
  e.preventDefault();

  dmpModal.style.display = "block";

  currentEditDay = e.target.dataset.jsEditMenu;
  currentEditDayNumber = parseInt(
    currentEditDay.charAt(currentEditDay.length - 1)
  );
  currentDayDisplay = days[currentEditDayNumber - 1];

  dmpModalHeader.textContent = `${currentDayDisplay} Menu Items`;

  inputFields.forEach((item) => {
    if (item.dataset.jsInputOne) {
      item.value = dmpContent[currentEditDay]["main"];
    } else if (item.dataset.jsInputTwo) {
      item.value = dmpContent[currentEditDay]["side1"];
    } else if (item.dataset.jsInputThree) {
      item.value = dmpContent[currentEditDay]["side2"];
    } else if (item.dataset.jsInputFour) {
      item.value = dmpContent[currentEditDay]["other"];
    } else if (item.dataset.jsInputFive) {
      item.value = dmpContent[currentEditDay]["notes"];
    }
  });

  let dmpModalMain = document.querySelector("[data-js-input-one]");
  dmpModalMain.focus();
  dmpModalMain.setSelectionRange(0, 100);
}

// handle event --> submit new dmp entries and save to local storage
submitMenuEdit.addEventListener("click", (e) => {
  e.preventDefault();

  dmpModal.style.display = "none";

  inputFields.forEach((item) => {
    if (item.dataset.jsInputOne) {
      dmpContent[currentEditDay]["main"] = item.value;
    } else if (item.dataset.jsInputTwo) {
      dmpContent[currentEditDay]["side1"] = item.value;
    } else if (item.dataset.jsInputThree) {
      dmpContent[currentEditDay]["side2"] = item.value;
    } else if (item.dataset.jsInputFour) {
      dmpContent[currentEditDay]["other"] = item.value;
    } else if (item.dataset.jsInputFive) {
      dmpContent[currentEditDay]["notes"] = item.value;
    }
  });

  //localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));
  loadMenuContent();
});

// handle event --> close modal without entering new information
dmpModalClose.addEventListener("click", (e) => {
  e.preventDefault();
  dmpModal.style.display = "none";
});

// *** EDIT DINNER MENU PLAN NOTES ENTRIES ***
// variables/constants for DOM manipulation
const editNotes = document.querySelectorAll("[data-js-edit-notes]");
const notesContainer = document.querySelector("[data-js-notes-container]");
const submitNotesEdit = document.querySelector("[data-js-notes-submit]");
const dmpNotesModal = document.querySelector("[data-js-notes-modal]");
const dmpNotesModalClose = document.querySelector(
  "[data-js-notes-modal-close]"
);
const dmpNotesModalInput = document.querySelector("[data-js-input-notes]");
const dmpNotesModalHeader = document.querySelector(
  "[data-js-dmp-notes-modal-header]"
);

// handle event --> button click to open dmp notes edit modal
editNotes.forEach((e) => e.addEventListener("click", openNotesEditModal));

// define function to open notes modal and populate existing data where applicable
function openNotesEditModal(e) {
  e.preventDefault();

  dmpNotesModal.style.display = "block";

  currentEditDay = e.target.dataset.jsEditNotes;
  currentEditDayNumber = parseInt(
    currentEditDay.charAt(currentEditDay.length - 1)
  );
  currentDayDisplay = days[currentEditDayNumber - 1];

  dmpNotesModalHeader.textContent = `${currentDayDisplay} Notes`;
  dmpNotesModalInput.value = dmpContent[currentEditDay]["notes"];
}

// handle event --> submit new dmp entries and save to local storage
submitNotesEdit.addEventListener("click", (e) => {
  e.preventDefault();

  dmpNotesModal.style.display = "none";

  let notes = currentEditDay + "Notes";

  dmpContent[currentEditDay]["notes"] = dmpNotesModalInput.value;

  notes.textContent = dmpContent[currentEditDay]["notes"];

  //localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));
  loadMenuContent();
});

// handle event --> close modal without entering new information
dmpNotesModalClose.addEventListener("click", (e) => {
  e.preventDefault();
  dmpNotesModal.style.display = "none";
});

// *** REORDER DAYS OF THE WEEK
// variables/constants for DOM manipulation
const reorderBtn = document.querySelector("[data-js-btn-reorder]");
const selectDay = document.querySelectorAll(".clickableDays");
const reorderClose = document.querySelector("[data-js-reorder-modal-close]");
const reorderModal = document.querySelector("[data-js-reorder-modal]");

// handle event --> button click to open modal
reorderBtn.addEventListener(
  "click",
  () => (reorderModal.style.display = "block")
);

// handle event --> select new first day of the week, close modal, repopulate days column accordingly, and save the new configuration to local storage
selectDay.forEach((e) => {
  e.addEventListener("click", function (e) {
    days1 = days.slice(days.indexOf(e.target.textContent));
    days2 = days.slice(0, days.indexOf(e.target.textContent));
    days1.push(...days2);
    days = days1;
    reorderModal.style.display = "none";

    //dotwPopulate();
    submitDOTW();
    // call function that sends updated array 'days' to /dotw via POST method
    //saveCurrentDOTW();
  });
});

//transfer update days array
function submitDOTW() {
  console.log("within submitDOTW " + JSON.stringify(days));

  let req = new XMLHttpRequest();
  req.open("POST", "/dotw");
  req.setRequestHeader("Content-Type", "application/json");
  req.send(JSON.stringify(days));
}

// function saveCurrentDOTW() {
//   client.hset(
//     "DOTW",
//     "day1",
//     "PLACEHOLDER",
//     "day2",
//     "PLACEHOLDER",
//     "day3",
//     "PLACEHOLDER",
//     "day4",
//     "PLACEHOLDER",
//     "day5",
//     "PLACEHOLDER",
//     "day6",
//     "PLACEHOLDER",
//     "day7",
//     "PLACEHOLDER"
//   );
// }

// handle event --> close modal without choosing a new first day
reorderClose.addEventListener(
  "click",
  () => (reorderModal.style.display = "none")
);

// *** CLEAR ALL MENU ITEMS
// variables/constants for DOM manipulation
const clearBtn = document.querySelector("[data-js-btn-clear]");
const clearYes = document.querySelector("[data-js-clear-yes]");
const clearNo = document.querySelector("[data-js-clear-no]");
const clearModal = document.querySelector("[data-js-clear-modal]");

// handle event --> button click to open modal
clearBtn.addEventListener("click", () => (clearModal.style.display = "block"));

// define functions to execute modal options
// exit without clearing items
let exitClearModal = () => (clearModal.style.display = "none");

// clear all items, save to local storage, reload menu content and exit
let clearAllMenuItems = function () {
  for (let i = 1; i < 8; i++) {
    currentEditDay = "day" + i;
    dmpContent[currentEditDay]["main"] = "";
    dmpContent[currentEditDay]["side1"] = "";
    dmpContent[currentEditDay]["side2"] = "";
    dmpContent[currentEditDay]["other"] = "";
    dmpContent[currentEditDay]["notes"] = "";
  }

  //localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));

  exitClearModal();
  loadMenuContent();
};

// handle event --> call function to clear all menu items
clearYes.addEventListener("click", clearAllMenuItems);

// handle event --> call function to exit without clearing all menu items
clearNo.addEventListener("click", exitClearModal);
// clearClose.addEventListener("click", exitClearModal);

// *** DRAG AND DROP FUNCTIONALITY FOR DMP CONTENT ***
// define dragstart handler and assign to all draggable elements
function dragstart_handler(e) {
  e.dataTransfer.setData("text/plain", e.target.dataset.jsDraggable);
}

function addDrag() {
  const dmpContentsDrag = document.querySelectorAll("[data-js-draggable]");

  dmpContentsDrag.forEach((e) =>
    e.addEventListener("dragstart", dragstart_handler)
  );
}

//define dragover and drop zone handlers and assign to all droppable elements
function dragover_handler(e) {
  dataFrom = e.dataTransfer.getData("text/plain");
  dataTo = e.currentTarget.dataset.jsDroppable;

  if (dataFrom !== dataTo) {
    e.preventDefault();
  }
}

function drop_handler(e) {
  e.preventDefault();

  let dmpContentFrom = dmpContent[dataFrom];
  let dmpContentTo = dmpContent[dataTo];

  dmpContent[dataTo] = dmpContentFrom;
  dmpContent[dataFrom] = dmpContentTo;

  loadMenuContent();

  //localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));
}

function addDropZone() {
  const dmpContentsDrop = document.querySelectorAll("[data-js-droppable]");

  dmpContentsDrop.forEach((e) => {
    e.addEventListener("dragover", dragover_handler);
    e.addEventListener("drop", drop_handler);
  });
}
