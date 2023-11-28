// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

export function fetchIndividualEntity(config) {
  document.addEventListener("DOMContentLoaded", function () {
    getEntities(config.item, "");
    infiniteScroll(config.item);
  });

  const input = document.getElementById(config.input);

  input.addEventListener("input", function (event) {
    const itemSelect = document.getElementById(config.itemSelect);
    if (event.target.value === "") {
      itemSelect.innerHTML = `<option disabled>select a ${config.type}</option>`;
      getEntities(config.item, "");
      infiniteScroll(config.item);
    } else {
      itemSelect.innerHTML = "";
      getEntities(config.item, event.target.value);
    }
  });
}

function getEntities(item, name) {
  fetchData(item, name, 1);
}

function infiniteScroll(item) {
  var selectElement = document.getElementById("infiniteScroll");
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
        fetchData(item, "", currentPageNo);
      }
    }

    lastScrollTop = st;
  });
}

let limit = 5;
function fetchData(item, name, page) {
  fetch(`/entities?item=${item}&limit=${limit}&name=${name}&page=${page}`, {
    method: "GET",
  })
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
