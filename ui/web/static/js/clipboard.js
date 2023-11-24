// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

//function to copy the ID to the clipboard
function copyToClipboard(button) {
	var clientIDElement = button.previousElementSibling.firstChild;
	var clientId = clientIDElement.textContent;

	navigator.clipboard.writeText(clientId).then(
		function () {
			//change the copy icon to indicate success
			button.innerHTML = `<i class="fas fa-check success-icon">`;
			setTimeout(function () {
				//revert the copy icon after a short delay
				button.innerHTML = `<i class ="far fa-copy">`;
			}, 1000);
		},
		function (error) {
			//handle error
			console.error("failed to copy to clipboard: ", error);
		},
	);
}

// Form validation functions

function validateName(name, errorDiv, event) {
	removeErrorMessage(errorDiv);
	if (name.trim() === "") {
		event.preventDefault();
		displayErrorMessage("Name is Required", errorDiv);
	}
}

const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
function validateEmail(email, errorDiv, event) {
	removeErrorMessage(errorDiv);
	if (email.trim() === "") {
		event.preventDefault();
		displayErrorMessage("Email is Required", errorDiv);
	} else if (!email.match(emailRegex)) {
		event.preventDefault();
		displayErrorMessage("Invalid email format", errorDiv);
	}
}

const minLength = 8;
function validatePassword(password, errorDiv, event) {
	removeErrorMessage(errorDiv);
	if (password.trim().length < minLength) {
		event.preventDefault();
		var errorMessage = `Password must be at least ${minLength} characters long`;
		displayErrorMessage(errorMessage, errorDiv);
	}
}

function validateMetadata(metadata, errorDiv, event) {
	removeErrorMessage(errorDiv);
	try {
		if (metadata.trim() !== "") {
			JSON.parse(metadata);
		}
	} catch (error) {
		event.preventDefault();
		displayErrorMessage("Metadata is not a valid JSON object", errorDiv);
	}
}

function validateTags(tags, errorDiv, event) {
	removeErrorMessage(errorDiv);
	var tagsArray;
	try {
		if (tags.trim() !== "") {
			tagsArray = JSON.parse(tags);
		}
	} catch (error) {
		event.preventDefault();
		displayErrorMessage("tags must be a string array", errorDiv);
	}
	if (
		!Array.isArray(tagsArray) ||
		!tagsArray.every(function (tag) {
			return typeof tag === "string";
		})
	) {
		event.preventDefault();
		displayErrorMessage("tags must be strings", errorDiv);
	}
}

function displayErrorMessage(errorMessage, divName) {
	const errorDiv = document.getElementById(divName);
	errorDiv.style.display = "block";
	errorDiv.innerHTML = errorMessage;
}

function removeErrorMessage(divName) {
	const errorDiv = document.getElementById(divName);
	errorDiv.style.display = "none";
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
