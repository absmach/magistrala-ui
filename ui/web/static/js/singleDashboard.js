// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
var gridClass = ".grid";
var grid = initGrid(layout);

// Editable canvas is used to make the canvas editable allowing the user to add widgets and be able to move the
// widgets around the canvas
function editableCanvas() {
  grid = editGrid(grid, layout);
}

function saveCanvas() {
  saveGrid(grid, dashboardID);
}

function cancelEdit() {
  cancelEditGrid(grid);
}
// Config has the ID, Content and Script parameters
function addEchartsWidget(chartData, config) {
  // Create a new grid item
  const newItem = document.createElement("div");
  newItem.className = "item";
  newItem.classList.add("item-editable");
  config = createChart(chartData, config);
  if (config.Style === undefined) {
    config.Style = {
      width: "400px",
      height: "400px",
    };
  }
  newItem.style.minWidth = config.Style.width;
  newItem.style.minHeight = config.Style.height;
  var styleString = `width: ${config.Style.width}; height: ${config.Style.height};`;
  newItem.innerHTML = `
  <div class="item-border">
    <button type="button" class="btn btn-sm" id="removeItem" onclick="removeGridItem(this.parentNode.parentNode);">
      <i class="fas fa-trash-can"></i>
    </button>
    <div class="item-content" id="${config.ID}" style="${styleString}">
      ${config.Content}
    </div>
  `;
  if (config.Script) {
    var scriptTag = document.createElement("script");
    scriptTag.type = "text/javascript";
    scriptTag.defer = true;
    scriptTag.innerHTML = config.Script;
    newItem.appendChild(scriptTag);
  }
  grid.add(newItem);
  resizeObserver.observe(newItem);
}

function addBootstrapWidget(chartData, config) {
  const newItem = document.createElement("div");
  newItem.className = "item";
  newItem.classList.add("item-editable");
  config = createChart(chartData, config);
  newItem.innerHTML = `
  <div class="item-border">
    <button type="button" class="btn btn-sm" id="removeItem" onclick="removeGridItem(this.parentNode.parentNode);">
      <i class="fas fa-trash-can"></i>
    </button>
    <div class="item-content" id="${config.ID}">
      ${config.Content}
    </div>
  `;

  grid.add(newItem);
  newItem.style.minWidth = newItem.clientWidth + "px";
  newItem.style.minHeight = newItem.clientHeight + "px";

  resizeObserver.observe(newItem);
}

function removeGridItem(item) {
  grid.remove(grid.getItems(item), { removeElements: true });
}

function openWidgetModal(widget) {
  const widgetModal = new bootstrap.Modal(document.getElementById(`${widget}Modal`));
  widgetModal.show();
}

function initGrid(layout) {
  if (layout) {
    loadLayout(layout);
  } else {
    showNoWidgetPlaceholder();
  }

  return grid;
}

function saveLayout(grid, dashboardID) {
  const itemData = grid.getItems().map((item) => {
    const itemElement = item._element;
    const itemContent = itemElement.querySelector(".item-content");
    // Extract the widget size
    const widgetWidth = itemContent.style.width;
    const widgetHeight = itemContent.style.height;

    // Extract the widget  position
    const positionLeft = itemElement.style.left;
    const positionTop = itemElement.style.top;
    const transform = itemElement.style.transform;
    const minWidth = itemElement.style.minWidth;
    const minHeight = itemElement.style.minHeight;

    return {
      widgetID: item._element.children[0].children[1].id,
      widgetSize: {
        width: widgetWidth,
        height: widgetHeight,
        minWidth: minWidth,
        minHeight: minHeight,
      },
      widgetPosition: {
        left: positionLeft,
        top: positionTop,
        transform: transform,
      },
    };
  });
  const gridState = {
    items: itemData,
  };

  // Convert the gridState to a JSON string
  const jsonString = JSON.stringify(gridState);

  // Update the metadata
  upMetadata = updateMetadata(jsonString, metadata);

  const dashboard = {
    id: dashboardID,
    layout: jsonString,
    metadata: JSON.stringify(upMetadata),
  };

  fetch(`${pathPrefix}/dashboards`, {
    method: "PATCH",
    body: JSON.stringify(dashboard),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((response) => {
    if (!response.ok) {
      const errorMessage = response.headers.get("X-Error-Message");
      console.log("Error: ", errorMessage);
    } else {
      window.location.reload();
    }
  });
}

function loadLayout(savedLayout) {
  try {
    const gridState = JSON.parse(savedLayout);
    // Clear the existing grid
    if (grid) {
      grid.destroy(true);
    }
    // Initialize a new grid with drag enabled or disabled based on saved state
    grid = new Muuri(gridClass, {
      dragEnabled: false,
      dragHandle: ".item-content",
    });

    if (gridState.items.length === 0) {
      showNoWidgetPlaceholder();
    } else {
      // Add items to the grid
      gridState.items.forEach((itemData) => {
        const newItem = document.createElement("div");
        newItem.className = "item";
        if (itemData.widgetPosition) {
          newItem.style.position = "absolute";
          newItem.style.left = itemData.widgetPosition.left;
          newItem.style.top = itemData.widgetPosition.top;
          if (itemData.widgetPosition.transform) {
            newItem.style.transform = itemData.widgetPosition.transform;
          }
        }
        defaultConfig = {
          ID: itemData.widgetID,
        };
        md = JSON.parse(metadata);
        chartData = md[itemData.widgetID];
        config = createChart(chartData, defaultConfig);
        var styleString = `width: ${itemData.widgetSize.width}; height: ${itemData.widgetSize.height};`;
        newItem.innerHTML = `
        <div class="item-border">
          <div class="item-content" id="${config.ID}" style="${styleString}">
            ${config.Content}
          </div>
        `;
        if (config.Script) {
          var scriptTag = document.createElement("script");
          scriptTag.type = "text/javascript";
          scriptTag.defer = true;
          scriptTag.innerHTML = config.Script;
          newItem.appendChild(scriptTag);
        }
        grid.add(newItem, { layout: true });
      });
    }
    // Layout the grid
    grid.layout();
  } catch (error) {
    console.error("Error loading grid state:", error);
  }
}

// Editable canvas is used to make the canvas editable allowing the user to add widgets and be able to move the
// widgets around the canvas
function editGrid(grid, layout) {
  removeNoWidgetPlaceholder();
  try {
    if (grid) {
      grid.destroy(true);
    }
    grid = new Muuri(gridClass, {
      dragEnabled: true,
      dragHandle: ".item-content",
    });
    if (layout) {
      const gridState = JSON.parse(layout);

      if (gridState) {
        gridState.items.forEach((itemData) => {
          const newItem = document.createElement("div");
          newItem.className = "item";
          newItem.classList.add("item-editable");
          if (itemData.widgetPosition) {
            newItem.style.position = "absolute";
            newItem.style.left = itemData.widgetPosition.left;
            newItem.style.top = itemData.widgetPosition.top;
            newItem.style.minWidth = itemData.widgetSize.minWidth;
            newItem.style.minHeight = itemData.widgetSize.minHeight;
            if (itemData.widgetPosition.transform) {
              newItem.style.transform = itemData.widgetPosition.transform;
            }
          }
          defaultConfig = {
            ID: itemData.widgetID,
          };
          md = JSON.parse(metadata);
          chartData = md[itemData.widgetID];
          config = createChart(chartData, defaultConfig);
          var styleString = `width: ${itemData.widgetSize.width}; height: ${itemData.widgetSize.height};`;
          newItem.innerHTML = `
          <div class="item-border">
            <button type="button" class="btn btn-sm" id="removeItem" onclick="removeGridItem(this.parentNode.parentNode);">
              <i class="fas fa-trash-can"></i>
            </button>
            <div class="item-content" id="${config.ID}" style="${styleString}">
              ${config.Content}
            </div>
          `;
          if (config.Script) {
            var scriptTag = document.createElement("script");
            scriptTag.type = "text/javascript";
            scriptTag.defer = true;
            scriptTag.innerHTML = config.Script;
            newItem.appendChild(scriptTag);
          }
          grid.add(newItem, { layout: true });
          resizeObserver.observe(newItem);
        });
        grid.layout();
      }
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

  return grid;
}

const previousSizes = new Map();

const resizeObserver = new ResizeObserver((entries) => {
  for (let entry of entries) {
    const { target } = entry;
    const previousSize = previousSizes.get(target) || {
      width: target.clientWidth,
      height: target.clientHeight,
    };
    const contentEl = target.querySelector(".item-content");
    const gridRightPosition = target.parentNode.getBoundingClientRect().right;
    const widgetRightPosition = target.getBoundingClientRect().right;
    const isOverflowing = widgetRightPosition > gridRightPosition;
    if (isOverflowing) {
      target.style.maxWidth = target.clientWidth + "px";
      target.style.maxHeight = target.clientHeight + "px";
    } else {
      target.style.maxWidth = "none";
      target.style.maxHeight = "none";
    }

    if (widgetRightPosition < gridRightPosition - 5) {
      // Calculate the change in width and height
      var widthChange = target.clientWidth - previousSize.width;
      var heightChange = target.clientHeight - previousSize.height;
      var itemContentWidth =
        parseInt(window.getComputedStyle(contentEl).getPropertyValue("width")) + widthChange;
      var itemContentHeight =
        parseInt(window.getComputedStyle(contentEl).getPropertyValue("height")) + heightChange;

      // Update the previous size for the next callback
      previousSizes.set(target, {
        width: target.clientWidth,
        height: target.clientHeight,
      });

      target.style.width = target.clientWidth + "px";
      target.style.height = target.clientHeight + "px";

      contentEl.style.width = itemContentWidth + "px";
      contentEl.style.height = itemContentHeight + "px";

      // Resize apache echarts chart
      const chart = echarts.getInstanceByDom(contentEl);
      if (chart) {
        chart.resize({
          width: itemContentWidth,
          height: itemContentHeight,
        });
      } else {
        const cardDiv = target.querySelector(".widgetcard");
        const h5Elem = cardDiv.querySelector("h5");
        const cardBody = cardDiv.querySelector(".card-body");
        const cardFooter = cardDiv.querySelector(".card-footer");

        if (entry.contentBoxSize) {
          // The standard makes contentBoxSize an array...
          if (entry.contentBoxSize[0]) {
            h5Elem.style.fontSize = Math.max(1, entry.contentBoxSize[0].inlineSize / 300) + "rem";
            if (cardBody) {
              cardBody.style.fontSize =
                Math.max(1.5, entry.contentBoxSize[0].inlineSize / 300) + "rem";
            }
            if (cardFooter) {
              cardFooter.style.fontSize =
                Math.max(1, entry.contentBoxSize[0].inlineSize / 600) + "rem";
            }
          } else {
            // ...but old versions of Firefox treat it as a single item
            h5Elem.style.fontSize = Math.max(1, entry.contentBoxSize.inlineSize / 300) + "rem";
            if (cardBody) {
              cardBody.style.fontSize =
                Math.max(1.5, entry.contentBoxSize.inlineSize / 300) + "rem";
            }
            if (cardFooter) {
              cardFooter.style.fontSize =
                Math.max(1, entry.contentBoxSize.inlineSize / 600) + "rem";
            }
          }
        } else {
          h5Elem.style.fontSize = `${Math.max(1, entry.contentRect.width / 300)}rem`;
          if (cardBody) {
            cardBody.style.fontSize = `${Math.max(1.5, entry.contentRect.width / 300)}rem`;
          }
          if (cardFooter) {
            cardFooter.style.fontSize = `${Math.max(1, entry.contentRect.width / 600)}rem`;
          }
        }
      }
      grid.refreshItems();
      grid.layout(true);
    }
  }
});

// Save the grid layout
function saveGrid(grid, dashboardID) {
  grid._settings.dragEnabled = false;
  document.querySelectorAll("#removeItem").forEach((item) => {
    item.classList.add("no-opacity");
    item.disabled = true;
  });
  saveLayout(grid, dashboardID);
}

// Cancel the grid layout
function cancelEditGrid(grid) {
  grid._settings.dragEnabled = false;
  window.location.reload();
}

// No widget placeholder
function showNoWidgetPlaceholder() {
  const noWidgetPlaceholder = document.querySelector(".no-widget-placeholder");
  noWidgetPlaceholder.classList.add("min-vh-50");
  const newPlaceholder = document.createElement("div");
  newPlaceholder.innerHTML = `
  <div class="row d-flex justify-content-center">
    <div class="col-lg-4 no-widget-box text-center fs-2 px-0">
      <button
        type="button"
        class="no-widget-button w-100 p-3"
        data-bs-toggle="offcanvas"
        data-bs-target="#widgetsCanvas"
        aria-controls="widgetsCanvas"
        onclick="editableCanvas()"
      >
        <i class="fas fa-plus"></i>
        <span>Add Widgets</span>
      </button>
    </div>
  </div>  
  `;

  noWidgetPlaceholder.appendChild(newPlaceholder);
}

function removeNoWidgetPlaceholder() {
  const noWidgetPlaceholder = document.querySelector(".no-widget-placeholder");
  noWidgetPlaceholder.remove();
  const gridContainer = document.querySelector(".grid");
  gridContainer.classList.add("min-vh-50");
}

function clearCanvas() {
  grid.remove(grid.getItems(), { removeElements: true });
}

function updateMetadata(layout, savedMetadata) {
  let upMetadata = {};
  // add metadata from the buffer
  if (savedMetadata !== "") {
    md = JSON.parse(savedMetadata);
    umd = { ...md, ...metadataBuffer };
  } else {
    umd = metadataBuffer;
  }

  // filter out any removed widgets
  if (layout) {
    const gridState = JSON.parse(layout);
    gridState.items.forEach((itemData) => {
      upMetadata[itemData.widgetID] = umd[itemData.widgetID];
    });
  }
  return upMetadata;
}
