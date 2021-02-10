// *** GLOBAL ***
// variables/constants for manipulating the DOM
let currentEditDay;
let currentEditDayNumber;
let currentDayDisplay;

// ***PAGE NAVIGATION***
const dmpLink = document.querySelectorAll("[data-js-nav-to-dinner]");
const sliLink = document.querySelectorAll("[data-js-nav-to-shopping-list]");
const dmpHeader = document.querySelector("[data-js-dmp-header]");
const dmpDisplay = document.querySelector("[data-js-dmp-display]");
const sliDisplay = document.querySelector("[data-js-sli-display]");

dmpLink.forEach((e) => e.addEventListener("click", navToDmp));

sliLink.forEach((e) => e.addEventListener("click", navToSli));

function navToDmp() {
  dmpDisplay.style.display = "flex";
  sliDisplay.style.display = "none";
  saveCurrentPage();
}

function navToSli() {
  dmpDisplay.style.display = "none";
  sliDisplay.style.display = "flex";
  saveCurrentPage();
}

// ***MENU PLAN PAGE***

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

// *** SETUP DATA PERSISTENCE VIA LOCAL STORAGE ***
// declare constants and variables --> local storage
const LOCAL_STORAGE_SHOPPINGLIST_KEY = "shopping.list";
const LOCAL_STORAGE_CURRENTPAGE_KEY = "current.page";
const LOCAL_STORAGE_CURRENTDOTW_KEY = "current.dotw";
const LOCAL_STORAGE_DMP_KEY = "dinnermenu.plan";

// load existing menu from local storage
if (localStorage.getItem(LOCAL_STORAGE_DMP_KEY) !== null) {
  dmpContent = JSON.parse(localStorage.getItem(LOCAL_STORAGE_DMP_KEY));
}

// // persist user's current page via local storage
let page;

if (localStorage.getItem(LOCAL_STORAGE_CURRENTPAGE_KEY) !== null) {
  page = JSON.parse(localStorage.getItem(LOCAL_STORAGE_CURRENTPAGE_KEY));
  dmpDisplay.style.display = page[0];
  sliDisplay.style.display = page[1];
} else {
  dmpDisplay.style.display = "flex";
  sliDisplay.style.display = "none";
}

function saveCurrentPage() {
  page = [dmpDisplay.style.display, sliDisplay.style.display];
  localStorage.setItem(LOCAL_STORAGE_CURRENTPAGE_KEY, JSON.stringify(page));
}

// persist user's days of the week (dotw) configuration via local storage
if (localStorage.getItem(LOCAL_STORAGE_CURRENTDOTW_KEY) !== null) {
  days = JSON.parse(localStorage.getItem(LOCAL_STORAGE_CURRENTDOTW_KEY));
} else {
}

function saveCurrentDOTW() {
  localStorage.setItem(LOCAL_STORAGE_CURRENTDOTW_KEY, JSON.stringify(days));
}

// *** POPULATE DAYS OF THE WEEK
const dotw1 = document.querySelector("[data-js-day1-dotw]");
const dotw2 = document.querySelector("[data-js-day2-dotw]");
const dotw3 = document.querySelector("[data-js-day3-dotw]");
const dotw4 = document.querySelector("[data-js-day4-dotw]");
const dotw5 = document.querySelector("[data-js-day5-dotw]");
const dotw6 = document.querySelector("[data-js-day6-dotw]");
const dotw7 = document.querySelector("[data-js-day7-dotw]");

const dotwClassSelect = document.querySelectorAll("[data-js-dotw]");

function dotwPopulate() {
  for (let i = 0; i < days.length; i++) {
    const dotwSpanCreate = document.createElement("span");
    let currentDayDOM = document.querySelector(
      '[data-js-dotw="day' + [i + 1] + '"]'
    );
    currentDayDOM.textContent = days[i].charAt(0);
    dotwSpanCreate.textContent = days[i];
    dotwSpanCreate.className = "tooltiptext";
    currentDayDOM.appendChild(dotwSpanCreate);
  }
}

// *** LOAD DINNER MENU PLAN CONTENT INTO PAGE
// define function to load content into page, assign to proper fields
// ami = 'all menu items'
function loadMenuContent() {
  console.log('Loading...');
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

// *** EDIT MENU ITEMS AND MENU ITEM NOTES

// *** EDIT DINNER MENU PLAN ENTRIES ***
// variables/constants for DOM manipulation
const dmpModal = document.querySelector("[data-js-dmp-modal]");
const editMenu = document.querySelectorAll("[data-js-edit-menu]");
const submitMenuEdit = document.querySelector("[data-js-new-item-submit]");
const dmpModalClose = document.querySelector("[data-js-dmp-modal-close]");
const inputFields = document.querySelectorAll(".modalFormInput");
const dmpModalHeader = document.querySelector("[data-js-dmp-modal-header]");

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

// handle event --> button click to call open dmp edit modal function
editMenu.forEach((e) => e.addEventListener("click", openEditModal));

// define function to open modal and populate existing data where applicable
function openEditModal(e) {
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

  localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));
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

  localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));
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

    dotwPopulate();
    saveCurrentDOTW();
  });
});

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

  localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));

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

  localStorage.setItem(LOCAL_STORAGE_DMP_KEY, JSON.stringify(dmpContent));
}

function addDropZone() {
  const dmpContentsDrop = document.querySelectorAll("[data-js-droppable]");

  dmpContentsDrop.forEach((e) => {
    e.addEventListener("dragover", dragover_handler);
    e.addEventListener("drop", drop_handler);
  });
}

// *** SHOPPING LIST PAGE ***

let list = []; // array to store shopping list items

// load existing shopping list items from local storage
// local storage key declared above
if (localStorage.getItem(LOCAL_STORAGE_SHOPPINGLIST_KEY) !== null) {
  list = JSON.parse(localStorage.getItem(LOCAL_STORAGE_SHOPPINGLIST_KEY));
}

// *** RENDER SHOPPING LIST AND LIST ITEM COUNT CONTENTS

// declare constants and variables --> render shopping list items
const listCount = document.querySelector("[data-js-list-count");
const listBody = document.querySelector("[data-js-list-body]");
const listItemTemplate = document.querySelector("#listItemTemplate");

// clear all existing list items from list body
function clearElement(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

//  render current count of remaining list items
function renderListCount() {
  const incompleteListCount = list.filter((list) => list.complete === false);
  const taskString = incompleteListCount.length === 1 ? "item" : "items";
  listCount.textContent = `${incompleteListCount.length} ${taskString} remaining`;
}

// render shopping list items in body of list
function renderShoppingList() {
  // clear all existing elements from list
  clearElement(listBody);
  // iterate through list array
  list.forEach((item) => {
    // create new list item for each array object
    const listItemElement = document.importNode(listItemTemplate.content, true);
    const checkbox = listItemElement.querySelector("input");
    checkbox.id = item.id;
    checkbox.checked = item.complete;
    const label = listItemElement.querySelector("label");
    label.htmlFor = item.id;
    const edit = listItemElement.querySelector(".sliEdit");
    edit.id = item.id;
    // conditionals to define how to render items depending on data entered
    if (item.units !== "") {
      if (item.quantity > 1) {
        if (item.units === "box") {
          label.append(
            item.name + ", " + item.quantity + " " + item.units + "es"
          );
          listBody.appendChild(listItemElement);
        } else {
          label.append(
            item.name + ", " + item.quantity + " " + item.units + "s"
          );
          listBody.appendChild(listItemElement);
        }
      } else {
        label.append(item.name + ", " + item.quantity + " " + item.units);
        listBody.appendChild(listItemElement);
      }
    } else {
      if (item.quantity > 1) {
        label.append(item.name + ", " + item.quantity);
        listBody.appendChild(listItemElement);
      } else {
        label.append(item.name);
        listBody.appendChild(listItemElement);
      }
    }

    // alternating background colors for list items
    const listItemBkgd = document.querySelectorAll(".listItem");

    listItemBkgd.forEach(function (item, index) {
      if (parseInt(index) % 2 === 0) {
        item.style.background = "#6b7a66";
        item.style.color = "white";
        item.classList.add = "listItemEven";
        item.firstElementChild.className = "sliCheckboxEven";
      }
    });
  });

  // add edit event handler
  const editItemBtn = document.querySelectorAll(".sliEdit");

  editItemBtn.forEach((e) => e.addEventListener("click", editSli));

  renderListCount();
}

// **** ADD SHOPPING LIST ITEM (SLI) ****
// declare constants and variables --> add new shopping list item
const addItemBtn = document.querySelector("[data-js-btn-add-item]");
const addItemModal = document.querySelector("[data-js-add-item-modal]");
const addItemForm = document.querySelector("[data-js-add-item-form]");
const addItemClose = document.querySelector("[data-js-add-item-close]");

const nliName = document.querySelector("[data-js-add-item-name]");
const nliType = document.querySelector("[data-js-add-item-type]");
const nliQty = document.querySelector("[data-js-add-item-quantity]");
const nliUnits = document.querySelector("[data-js-add-item-units]");

let editItemId;

// handle event --> shopping list add item button
addItemBtn.addEventListener("click", () => {
  addItemModal.style.display = "block";
  addItemForm.dataset.jsAddItemForm = "new";
  nliName.focus();
});

// handle event --> close add item modal without adding new item
addItemClose.addEventListener(
  "click",
  () => (addItemModal.style.display = "none")
);

// handle event --> check new or edit, submit new item/changes, close add item modal

addItemForm.addEventListener("submit", (e) => {
  e.preventDefault();

  if (nliName.value == null || nliName.value === "") return;

  if (addItemForm.dataset.jsAddItemForm === "new") {
    let newObject = {
      id: Date.now().toString(),
      name: nliName.value,
      type: nliType.value,
      quantity: nliQty.value,
      units: nliUnits.value,
      complete: false,
    };

    list.push(newObject);
    nliName.value = "";
    nliType.value = "";
    nliQty.value = "1";
    nliUnits.value = "";
  } else if (addItemForm.dataset.jsAddItemForm === "edit") {
    list.forEach((item, index) => {
      if (item.id === editItemId) {
        list[index].name = nliName.value;
        list[index].type = nliType.value;
        list[index].quantity = nliQty.value;
        list[index].units = nliUnits.value;

        nliName.value = "";
        nliType.value = "";
        nliQty.value = "1";
        nliUnits.value = "";
      }
    });
  }

  addItemModal.style.display = "none";

  localStorage.setItem(LOCAL_STORAGE_SHOPPINGLIST_KEY, JSON.stringify(list));

  renderShoppingList();
});

// **** MANAGE EXISTING LIST ITEMS ****

// handle event --> shopping list edit item button
function editSli(e) {
  editItemId = e.target.id;
  console.log(editItemId);

  const modal = document.querySelector("[data-js-add-item-form]");
  console.log(modal);
  modal.dataset.jsAddItemForm = "edit";
  console.log(modal.dataset.jsAddItemForm);

  list.forEach((item, index) => {
    if (item.id === editItemId) {
      addItemModal.style.display = "block";

      nliName.value = list[index].name;
      nliType.value = list[index].type;
      nliQty.value = list[index].quantity;
      nliUnits.value = list[index].units;
    } else {
      console.log("nope");
    }
  });

  // addItemModal.style.display = "block";

  // nliName.value = editItemTarget[0].name;
  // nliType.value = editItemTarget[0].type;
  // nliQty.value = editItemTarget[0].quantity;
  // nliUnits.value = editItemTarget[0].units;

  // let editItemTarget = list.filter((list) => list.id === itemId);

  // addItemModal.style.display = "block";

  // nliName.value = editItemTarget[0].name;
  // nliType.value = editItemTarget[0].type;
  // nliQty.value = editItemTarget[0].quantity;
  // nliUnits.value = editItemTarget[0].units;

  nliName.focus();
}

// event handler --> mark sli as completed, save to local storage
listBody.addEventListener("click", (e) => {
  if (e.target.tagName.toLowerCase() === "input") {
    let selectedListItem = list.find((list) => list.id === e.target.id);
    selectedListItem.complete = e.target.checked;
  }
  localStorage.setItem(LOCAL_STORAGE_SHOPPINGLIST_KEY, JSON.stringify(list));
  renderListCount();
});

// declare constants and variables --> clear completed shopping list items
const completedItemsBtn = document.querySelector(
  "[data-js-btn-clear-completed]"
);
const completedItemsModal = document.querySelector(
  "[data-js-clear-completed-modal]"
);
const clearCompletedYes = document.querySelector(
  "[data-js-clear-completed-yes]"
);
const clearCompletedNo = document.querySelector("[data-js-clear-completed-no]");

// event handler --> clear completed items button, opens confirmation modal
// if no applicable items opens informational modal
completedItemsBtn.addEventListener("click", () => {
  completedItemsCheck = list.filter((list) => list.complete === true);

  if (completedItemsCheck.length > 0) {
    completedItemsModal.style.display = "block";
  } else {
    noItemsToClearModal.style.display = "block";
  }
});

// define function to clear completed sli from list, save to local storage
function clearCompletedItems() {
  list = list.filter((list) => list.complete === false);

  localStorage.setItem(LOCAL_STORAGE_SHOPPINGLIST_KEY, JSON.stringify(list));
  completedItemsModal.style.display = "none";
  renderShoppingList();
  renderListCount();
}

// event handler --> clear completed items confirmation
clearCompletedYes.addEventListener("click", clearCompletedItems);

// event handler --> close clear completed items modal without clearing items
clearCompletedNo.addEventListener(
  "click",
  () => (completedItemsModal.style.display = "none")
);

// declare constants and variables --> clear all shopping list items
const allItemsBtn = document.querySelector("[data-js-btn-clear-all]");
const allItemsModal = document.querySelector("[data-js-clear-all-modal]");
const clearAllYes = document.querySelector("[data-js-clear-all-yes]");
const clearAllNo = document.querySelector("[data-js-clear-all-no]");

// event handler --> clear all items button, opens confirmation modal
// if no applicable items opens informational modal
allItemsBtn.addEventListener("click", () => {
  if (list.length > 0) {
    allItemsModal.style.display = "block";
  } else {
    noItemsToClearModal.style.display = "block";
  }
});

// define function to clear all sli from list, save to local storage
function clearAllSli() {
  list = [];
  allItemsModal.style.display = "none";
  localStorage.setItem(LOCAL_STORAGE_SHOPPINGLIST_KEY, JSON.stringify(list));
  renderShoppingList();
  renderListCount();
}

// event handler --> clear all items confirmation
clearAllYes.addEventListener("click", clearAllSli);

// event handler --> close clear all items modal without clearing items
clearAllNo.addEventListener(
  "click",
  () => (allItemsModal.style.display = "none")
);

// declare constants and variables --> no shopping list items to clear
const noItemsToClearModal = document.querySelector("[data-js-no-items-modal]");
const noItemsModalClose = document.querySelector("[data-js-no-items-close");

// event handler --> close no items to clear modal
// opened when there are no applicable items to clear
noItemsModalClose.addEventListener(
  "click",
  () => (noItemsToClearModal.style.display = "none")
);

// populate days of the week and menu content, add event listeners for drag and drop functionality, render shopping list items upon first loading page
document.addEventListener("DOMContentLoaded", (e) => {
  dotwPopulate();
  loadMenuContent();
  addDrag();
  addDropZone();
  renderShoppingList();
});

// **** ALL CODE ABOVE HAS BEEN CLEANED UP AS OF 10/01 ****
