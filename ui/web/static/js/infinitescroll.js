// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

export function fetchIndividualEntity(config) {
  if (config.item === "members") {
    config.permission = "member";
  } else {
    config.permission = "";
  }
  document.addEventListener("DOMContentLoaded", function () {
    getEntities(config, "");
    infiniteScroll(config);
  });

  const input = document.getElementById(config.input);

  input.addEventListener("input", function (event) {
    const itemSelect = document.getElementById(config.itemSelect);
    if (event.target.value === "") {
      itemSelect.innerHTML = `<option disabled>select a ${config.type}</option>`;
      getEntities(config, "");
      infiniteScroll(config);
    } else {
      itemSelect.innerHTML = "";
      getEntities(config, event.target.value);
    }
  });
}

function getEntities(config, name) {
  fetchData({
    item: config.item,
    domain: config.domain,
    permission: config.permission,
    name: name,
    page: 1,
  });
}

function infiniteScroll(config) {
  var selectElement = document.getElementById(config.itemSelect);
  var singleOptionHeight = selectElement.querySelector("option").offsetHeight;
  var selectBoxHeight = selectElement.offsetHeight;
  var numOptionsBeforeLoad = 2;
  var lastScrollTop = 0;
  var currentPageNo = 1;
  var currentScroll = 0;

  selectElement.addEventListener("scroll", function () {
    var st = selectElement.scrollTop;
    var totalHeight = selectElement.querySelectorAll("option").length * singleOptionHeight;

    if (st > lastScrollTop) {
      currentScroll = st + selectBoxHeight;
      if (currentScroll + numOptionsBeforeLoad * singleOptionHeight >= totalHeight) {
        currentPageNo++;
        fetchData({
          item: config.item,
          item: config.item,
          name: "",
          domain: config.domain,
          permission: config.permission,
          page: currentPageNo,
        });
      }
    }

    lastScrollTop = st;
  });
}

let limit = 5;
function fetchData(config) {
  fetch(
    `/entities?item=${config.item}&limit=${limit}&name=${config.name}&page=${config.page}&domain=${config.domain}&permission=${config.permission}`,
    {
      method: "GET",
    },
  )
    .then((response) => response.json())
    .then((data) => {
      const selectElement = document.getElementById("infiniteScroll");
      data.data.forEach((entity) => {
        const option = document.createElement("option");
        option.value = entity.id;
        option.text = entity.name;
        selectElement.appendChild(option);
      });
    })
    .catch((error) => console.error("Error:", error));
}
