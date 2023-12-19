// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

let colorIndex = 0;

function addItem(event, inputId, listId) {
  if (event.key === "Enter") {
    event.preventDefault();

    const itemInput = document.getElementById(inputId);
    const itemList = document.getElementById(listId);

    if (itemInput && itemList) {
      const newItem = document.createElement("div");
      newItem.textContent = itemInput.value;
      newItem.className = "mb-2 highlight-list-item";
      newItem.style.backgroundColor = generateColor();
      itemList.appendChild(newItem);
      itemInput.value = "";
    }
  }
}

function generateColor() {
  const colors = ["#FF7F50", "#FFD700", "#32CD32", "#87CEEB", "#FF69B4"];
  const color = colors[colorIndex % colors.length];
  colorIndex++;
  return color;
}

function deleteItem(event) {
  const target = event.target;
  if (target.className === "highlight-list-item") {
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
