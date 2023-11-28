// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

export function displayErrorMessage(errorMessage, divName) {
  const errorDiv = document.getElementById(divName);
  errorDiv.style.display = "block";
  errorDiv.innerHTML = errorMessage;
}

export function removeErrorMessage(divName) {
  const errorDiv = document.getElementById(divName);
  errorDiv.style.display = "none";
}
