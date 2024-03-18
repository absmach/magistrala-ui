// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
const gridClass = ".grid";
const editableGridClass = ".grid-editable";
var grid = initGrid(layout);
const gridSize = 25;
const previousSizes = new Map();
let isResizing = false;
let currentFinalizeResizeFunction = null;

function cancelEdit() {
  grid._settings.dragEnabled = false;
  window.location.reload();
}

function addWidget(chartData, widgetID) {
  let newItem = new Widget(chartData, widgetID);
  grid.add(newItem.element);
  resizeObserver.observe(newItem.element);
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

function saveLayout() {
  const itemData = grid.getItems().map((item) => {
    const itemElement = item._element;
    const itemContent = itemElement.querySelector(".item-content");
    // Extract the widget size
    const { width, height } = itemContent.style;

    // Extract the widget  position
    const { left, top, transform, minWidth, minHeight } = itemElement.style;

    return {
      widgetID: item._element.children[0].children[1].id,
      widgetSize: { width, height, minWidth, minHeight },
      widgetPosition: { left, top, transform },
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
    if (grid) {
      grid.destroy(true);
    }
    grid = new Muuri(gridClass, {
      dragEnabled: false,
      dragHandle: ".item-content",
    });
    if (gridState.items.length === 0) {
      showNoWidgetPlaceholder();
    } else {
      const metadataObj = JSON.parse(metadata);
      gridState.items.forEach((itemData) => {
        const chartData = metadataObj[itemData.widgetID];
        const widget = new Widget(chartData, itemData.widgetID);
        const newItem = widget.element;
        newItem.classList.remove("item-editable");
        const removeButton = newItem.querySelector("#removeItem");
        if (removeButton) {
          removeButton.classList.add("no-opacity");
          removeButton.disabled = true;
        }
        const { widgetPosition, widgetSize } = itemData;
        if (widgetPosition) {
          Object.assign(newItem.style, {
            position: "absolute",
            left: widgetPosition.left,
            top: widgetPosition.top,
            transform: widgetPosition.transform || "",
          });
        }
        const contentEl = newItem.querySelector(".item-content");
        Object.assign(contentEl.style, {
          width: widgetSize.width,
          height: widgetSize.height,
        });
        grid.add(newItem);
      });
    }
    grid.layout();
  } catch (error) {
    console.error("Error loading grid state:", error);
  }
}

// Editable canvas is used to make the canvas editable allowing the user to add widgets and be able to move the
// widgets around the canvas
function editableCanvas() {
  removeNoWidgetPlaceholder();
  let ltgrid = document.querySelector(".grid");
  ltgrid.classList.add("grid-editable");
  try {
    if (grid) {
      grid.destroy(true);
    }
    grid = new Muuri(editableGridClass, {
      dragEnabled: true,
      dragHandle: ".item-content",
    });
    if (layout) {
      const gridState = JSON.parse(layout);
      if (gridState) {
        const metadataObj = JSON.parse(metadata);
        gridState.items.forEach((itemData) => {
          const chartData = metadataObj[itemData.widgetID];
          const widget = new Widget(chartData, itemData.widgetID);
          const newItem = widget.element;
          const { widgetPosition, widgetSize } = itemData;
          if (widgetPosition) {
            Object.assign(newItem.style, {
              position: "absolute",
              left: widgetPosition.left,
              top: widgetPosition.top,
              minWidth: widgetSize.minWidth,
              minHeight: widgetSize.minHeight,
              transform: widgetPosition.transform || "",
            });
          }
          const contentEl = newItem.querySelector(".item-content");
          Object.assign(contentEl.style, {
            width: widgetSize.width,
            height: widgetSize.height,
          });
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
      let widthChange = target.clientWidth - previousSize.width;
      let heightChange = target.clientHeight - previousSize.height;
      let itemContentWidth =
        parseInt(window.getComputedStyle(contentEl).getPropertyValue("width")) + widthChange;
      let itemContentHeight =
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

      //Resize the widget content
      resizeWidgetContent(target, entry, itemContentWidth, itemContentHeight);

      grid.refreshItems();
      grid.layout(true);
      if (!isResizing) {
        isResizing = true;

        if (currentFinalizeResizeFunction) {
          document.removeEventListener("mouseup", currentFinalizeResizeFunction);
          currentFinalizeResizeFunction = null;
        }
        currentFinalizeResizeFunction = function () {
          snapToGrid(target, entry);
        };
        document.addEventListener("mouseup", currentFinalizeResizeFunction);
      }
    }
  }
});

function snapToGrid(target, entry) {
  const previousSize = previousSizes.get(target) || {
    width: target.clientWidth,
    height: target.clientHeight,
  };
  const contentEl = target.querySelector(".item-content");
  const snapToGrid = (size) => Math.round(size / gridSize) * gridSize;
  let snappedWidth = snapToGrid(target.clientWidth);
  let snappedHeight = snapToGrid(target.clientHeight);

  let widthChange = snappedWidth - previousSize.width;
  let heightChange = snappedHeight - previousSize.height;
  let itemContentWidth =
    parseInt(window.getComputedStyle(contentEl).getPropertyValue("width")) + widthChange;
  let itemContentHeight =
    parseInt(window.getComputedStyle(contentEl).getPropertyValue("height")) + heightChange;

  target.style.width = snappedWidth + "px";
  target.style.height = snappedHeight + "px";

  contentEl.style.width = itemContentWidth + "px";
  contentEl.style.height = itemContentHeight + "px";

  previousSizes.set(target, {
    width: snappedWidth,
    height: snappedHeight,
  });

  resizeWidgetContent(target, entry, itemContentWidth, itemContentHeight);
  document.removeEventListener("mouseup", currentFinalizeResizeFunction);
  isResizing = false;
}

function resizeWidgetContent(target, entry, itemContentWidth, itemContentHeight) {
  const contentEl = target.querySelector(".item-content");
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

    if (target.contentBoxSize) {
      // The standard makes contentBoxSize an array...
      if (entry.contentBoxSize[0]) {
        h5Elem.style.fontSize = Math.max(1, entry.contentBoxSize[0].inlineSize / 300) + "rem";
        if (cardBody) {
          cardBody.style.fontSize = Math.max(1.5, entry.contentBoxSize[0].inlineSize / 300) + "rem";
        }
        if (cardFooter) {
          cardFooter.style.fontSize = Math.max(1, entry.contentBoxSize[0].inlineSize / 600) + "rem";
        }
      } else {
        // ...but old versions of Firefox treat it as a single item
        h5Elem.style.fontSize = Math.max(1, entry.contentBoxSize.inlineSize / 300) + "rem";
        if (cardBody) {
          cardBody.style.fontSize = Math.max(1.5, entry.contentBoxSize.inlineSize / 300) + "rem";
        }
        if (cardFooter) {
          cardFooter.style.fontSize = Math.max(1, entry.contentBoxSize.inlineSize / 600) + "rem";
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

// Set dynamic parameters for all the modals
document.addEventListener("DOMContentLoaded", function () {
  // Get the current formatted date and time
  function formatDateTime(date) {
    let formatted = new Date(date.getTime() - date.getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 16);
    return formatted;
  }

  let now = new Date();
  let formattedNow = formatDateTime(now);
  let startTimes = document.querySelectorAll("#start-time");
  let stopTimes = document.querySelectorAll("#stop-time");

  // Set the max attribute for the start and stop times
  startTimes.forEach(function (startTime) {
    startTime.setAttribute("max", formattedNow);
  });

  stopTimes.forEach(function (stopTime) {
    stopTime.setAttribute("max", formattedNow);
  });
});
