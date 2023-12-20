// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

let colorIndex = 0;

function addItem(event, inputId, listId) {
  if (event.key === "Enter") {
    event.preventDefault();

    const itemInput = document.getElementById(inputId);
    const itemList = document.getElementById(listId);

    if (itemInput && itemList && itemInput.value.trim() !== "") {
      const newItem = document.createElement("div");
      newItem.textContent = itemInput.value;
      newItem.className = "mb-2 buttons highlight-list-item";
      itemList.appendChild(newItem);
      itemInput.value = "";
    }
  }
}


function deleteItem(event) {
  const target = event.target;
  if (target.classList.contains("highlight-list-item")) {
    target.remove();
  }
}

function submitItemList(inputId, listId) {
  const itemList = document.getElementById(listId);
  const listItems = itemList.getElementsByClassName("highlight-list-item");
  const itemsArray = Array.from(listItems).map((item) => item.textContent.trim());
  const jsonData = JSON.stringify(itemsArray);
  const jsonInput = document.getElementById(inputId);
  jsonInput.value = jsonData;
}
