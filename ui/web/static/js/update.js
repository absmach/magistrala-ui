// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { submitUpdateForm } from "./forms.js";
import {
  validateName,
  validateEmail,
  validateJSON,
  validateStringArray,
  validatePassword,
} from "./validation.js";

import { removeErrorMessage } from "./errors.js";

function updateName(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function (event) {
    const updatedValue = config.cell.textContent.trim();
    if (validateName(updatedValue, config.alertDiv, config.fieldName, event)) {
      const url = `/${config.entity}/${config.id}`;
      const data = { [config.field]: updatedValue };

      submitUpdateForm({
        url: url,
        data: data,
        alertDiv: config.alertDiv,
        field: config.field,
      });
    }
  });
}

function updateIdentity(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function (event) {
    const updatedValue = config.cell.textContent.trim();
    if (validateEmail(updatedValue, config.alertDiv, config.fieldName, event)) {
      const url = `/${config.entity}/${config.id}/identity`;
      const data = { [config.field]: updatedValue };

      submitUpdateForm({
        url: url,
        data: data,
        alertDiv: config.alertDiv,
      });
    }
  });
}

function updateMetadata(config) {
  const button = document.getElementById(config.button);
  button.addEventListener("click", function (event) {
    event.preventDefault();
    const updatedValue = document.getElementById(config.textArea).value;
    if (validateJSON(updatedValue, config.alertDiv, config.fieldName, event)) {
      const url = `/${config.entity}/${config.id}`;
      const data = { [config.field]: JSON.parse(updatedValue) };

      submitUpdateForm({
        url: url,
        data: data,
        alertDiv: config.alertDiv,
        field: config.field,
      });
    }
  });
}

function updateTags(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function (event) {
    const updatedValue = config.cell.textContent.trim();
    if (validateStringArray(updatedValue, config.alertDiv, config.fieldName, event)) {
      const url = `/${config.entity}/${config.id}/tags`;
      const data = { [config.field]: JSON.parse(updatedValue) };

      submitUpdateForm({
        url: url,
        data: data,
        alertDiv: config.alertDiv,
      });
    }
  });
}

function updateSecret(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function (event) {
    const updatedValue = config.cell.textContent.trim();
    if (validatePassword(updatedValue, config.alertDiv, config.fieldName, event)) {
      const url = `/${config.entity}/${config.id}/secret`;
      const data = { [config.field]: updatedValue };

      submitUpdateForm({
        url: url,
        data: data,
        alertDiv: config.alertDiv,
      });
    }
  });
}

function updateDescription(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function () {
    const updatedValue = config.cell.textContent.trim();
    const url = `/${config.entity}/${config.id}`;
    const data = { [config.field]: updatedValue };

    submitUpdateForm({
      url: url,
      data: data,
      alertDiv: config.alertDiv,
      field: config.field,
    });
  });
}

// Bootstrap update functions
function updateContent(config) {
  const button = document.getElementById(config.button);
  button.addEventListener("click", function (event) {
    event.preventDefault();
    const updatedValue = document.getElementById(config.textArea).value;
    if (validateJSON(updatedValue, config.alertDiv, config.fieldName, event)) {
      const url = `/${config.entity}/${config.id}`;
      const data = { [config.field]: updatedValue };

      submitUpdateForm({
        url: url,
        data: data,
        alertDiv: config.alertDiv,
        field: config.field,
      });
    }
  });
}

function updateClientCerts(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function () {
    const updatedValue = config.cell.textContent.trim();
    const url = `/${config.entity}/${config.id}/certs`;
    const data = { [config.field]: updatedValue };

    submitUpdateForm({
      url: url,
      data: data,
      alertDiv: config.alertDiv,
    });
  });
}

// make a cell editable.
function makeEditable(cell) {
  cell.setAttribute("contenteditable", "true");
  cell.dataset.originalContent = cell.innerHTML;
}

// make cell uneditable.
function makeUneditable(cell) {
  const originalContent = cell.dataset.originalContent;
  cell.innerHTML = originalContent;
  cell.setAttribute("contenteditable", "false");
}

// function show the save/cancel buttons and hide the edit button.
function showSaveCancelButtons(editBtn, saveCancelBtn) {
  editBtn.style.display = "none";
  saveCancelBtn.style.display = "inline-block";
}

// function to show the edit button anf hide the save/cancel buttons.
function showEditButton(editBtn, saveCancelBtn) {
  editBtn.style.display = "inline-block";
  saveCancelBtn.style.display = "none";
}

// config parameters are: button, field
function editRow(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function () {
    makeEditable(config.cell);
    showSaveCancelButtons(config.editBtn, config.saveCancelBtn);
  });
}

function cancelEditRow(config) {
  const button = document.getElementById(config.button);

  button.addEventListener("click", function () {
    makeUneditable(config.cell);
    showEditButton(config.editBtn, config.saveCancelBtn);
    removeErrorMessage(config.alertDiv, config.fieldName);
  });
}

function attachEditRowListener(config) {
  for (const key in config.rows) {
    if (config.rows.hasOwnProperty(key)) {
      const cell = document.querySelector(`td[data-field="${key}"]`);
      const editBtn = cell.parentNode.querySelector(".edit-btn");
      const saveCancelBtn = cell.parentNode.querySelector(".save-cancel-buttons");
      editRow({
        button: `edit-${key}`,
        cell: cell,
        editBtn: editBtn,
        saveCancelBtn: saveCancelBtn,
      });
      cancelEditRow({
        button: `cancel-${key}`,
        cell: cell,
        editBtn: editBtn,
        saveCancelBtn: saveCancelBtn,
        alertDiv: config.errorDiv,
        fieldName: config.fields[key],
      });
      const saveRow = config.rows[key];
      saveRow({
        button: `save-${key}`,
        field: key,
        cell: cell,
        editBtn: editBtn,
        saveCancelBtn: saveCancelBtn,
        id: config.id,
        entity: config.entity,
        alertDiv: config.errorDiv,
        fieldName: config.fields[key],
      });
    }
  }
}

export {
  updateName,
  updateIdentity,
  updateMetadata,
  updateTags,
  updateSecret,
  updateDescription,
  updateContent,
  updateClientCerts,
  attachEditRowListener,
};
