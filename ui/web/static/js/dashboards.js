// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
var grid;
var gridClass = ".grid";
var localStorageKey = "gridState";

function initGrid() {
  var savedLayout = window.localStorage.getItem(localStorageKey);
  if (savedLayout) {
    loadLayout(savedLayout);
  } else {
    grid = new Muuri(gridClass, {
      dragEnabled: true,
    });
  }

  return grid;
}

function saveLayout(grid, localStorageKey) {
  const itemData = grid.getItems().map((item) => ({
    innerHTML: item.getElement().innerHTML,
  }));

  const gridState = {
    items: itemData,
    layout: grid._layout,
    settings: {
      dragEnabled: grid._settings.dragEnabled,
      // Add other relevant settings if needed
    },
  };

  // Convert the gridState to a JSON string
  const jsonString = JSON.stringify(gridState, function (key, value) {
    // Exclude circular references
    if (key === "_item" || key === "_grid" || key === "_layout") {
      return undefined;
    }
    return value;
  });

  localStorage.setItem(localStorageKey, jsonString);
}

function loadLayout(savedLayout) {
  try {
    const gridState = JSON.parse(savedLayout);
    // Clear the existing grid
    if (grid) {
      grid.destroy(true);
    }

    grid = new Muuri(gridClass, {
      dragEnabled: gridState.settings.dragEnabled,
      // Add any other relevant settings
    });

    // Add items to the grid based on the saved state
    gridState.items.forEach((itemData) => {
      const newItem = document.createElement("div");
      newItem.className = "item";
      newItem.innerHTML = itemData.innerHTML.trim();
      const item = grid.add(newItem);
    });

    // Layout the grid
    grid.layout(gridState.layout);
  } catch (error) {
    console.error("Error loading grid state:", error);
  }
}

// Editable canvas is used to make the canvas editable allowing the user to add widgets and be able to move the
// widgets around the canvas
function editGrid(grid) {
  var savedLayout = window.localStorage.getItem(localStorageKey);
  try {
    const gridState = JSON.parse(savedLayout);
    if (grid) {
      grid.destroy(true);
    }
    grid = new Muuri(gridClass, {
      dragEnabled: true,
    });
    if (gridState) {
      gridState.items.forEach((itemData) => {
        const newItem = document.createElement("div");
        newItem.className = "item";
        newItem.innerHTML = itemData.innerHTML.trim();
        const item = grid.add(newItem);
      });
      grid.layout(gridState.layout);
    }
  } catch (error) {
    console.error("Error loading grid state:", error);
  }

  document.getElementById("editableCanvasButton").classList.add("display-none");
  document.getElementById("CanvasButtons").classList.remove("display-none");
  document.querySelectorAll("#removeItem").forEach((item) => {
    item.classList.remove("no-opacity");
    item.disabled = false;
  });
  document.querySelectorAll(".item").forEach((item) => {
    item.classList.add("item-editable");
  });

  return grid;
}

// Save the grid layout
function saveGrid(grid) {
  grid._settings.dragEnabled = false;
  document.querySelectorAll("#removeItem").forEach((item) => {
    item.classList.add("no-opacity");
    item.disabled = true;
  });
  saveLayout(grid, localStorageKey);
  window.location.reload();
}

// Cancel the grid layout
function cancelEditGrid(grid) {
  grid._settings.dragEnabled = false;
  window.location.reload();
}
