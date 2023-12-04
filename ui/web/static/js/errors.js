// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

export function displayErrorMessage(errorMessage, divName, fieldName) {
  const errorDiv = document.getElementById(divName);
  const errorField = document.querySelector(`.${fieldName}`);
  errorDiv.style.display = "block";
  errorDiv.innerHTML = errorMessage;
  errorField.classList.add("border-red");
}

export function removeErrorMessage(divName, fieldName) {
  const errorDiv = document.getElementById(divName);
  const errorField = document.querySelector(`.${fieldName}`);

  errorDiv.style.display = "none";
  errorField.classList.remove("border-red");
}
