// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { displayErrorMessage, removeErrorMessage } from "./errors.js";

const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
const minLength = 8;

function validateName(name, errorDiv, event) {
  removeErrorMessage(errorDiv);
  if (name.trim() === "") {
    event.preventDefault();
    displayErrorMessage("Name is Required", errorDiv);
    return false;
  }
  return true;
}

function validateEmail(email, errorDiv, event) {
  removeErrorMessage(errorDiv);
  if (email.trim() === "") {
    event.preventDefault();
    displayErrorMessage("Email is Required", errorDiv);
    return false;
  } else if (!email.match(emailRegex)) {
    event.preventDefault();
    displayErrorMessage("Invalid email format", errorDiv);
    return false;
  }
  return true;
}

function validatePassword(password, errorDiv, event) {
  removeErrorMessage(errorDiv);
  if (password.trim().length < minLength) {
    event.preventDefault();
    var errorMessage = `Password must be at least ${minLength} characters long`;
    displayErrorMessage(errorMessage, errorDiv);
    return false;
  }
  return true;
}

function validateJSON(data, errorDiv, event) {
  removeErrorMessage(errorDiv);
  try {
    if (data.trim() !== "") {
      JSON.parse(data);
    }
  } catch (error) {
    event.preventDefault();
    displayErrorMessage("not a valid JSON object", errorDiv);
    return false;
  }
  return true;
}

function validateStringArray(tags, errorDiv, event) {
  removeErrorMessage(errorDiv);
  var tagsArray;
  try {
    if (tags.trim() !== "") {
      tagsArray = JSON.parse(tags);
    }
    if (
      !Array.isArray(tagsArray) ||
      !tagsArray.every(function (tag) {
        return typeof tag === "string";
      })
    ) {
      event.preventDefault();
      displayErrorMessage("must be strings in an array", errorDiv);
      return false;
    }
  } catch (error) {
    event.preventDefault();
    displayErrorMessage("must be a string array", errorDiv);
    return false;
  }

  return true;
}

function attachValidationListener(config) {
  const button = document.getElementById(config.buttonId);

  button.addEventListener("click", function (event) {
    for (const key in config.validations) {
      if (config.validations.hasOwnProperty(key)) {
        const validationFunc = config.validations[key];
        const elementValue = document.getElementById(key).value;
        validationFunc(elementValue, config.errorDivs[key], event);
      }
    }
  });
}

export {
  validateName,
  validateEmail,
  validatePassword,
  validateJSON,
  validateStringArray,
  attachValidationListener,
};
