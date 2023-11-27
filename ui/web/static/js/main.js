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
		return false;
	}
	return true;
}

const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
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

const minLength = 8;
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

function validateMetadata(metadata, errorDiv, event) {
	removeErrorMessage(errorDiv);
	try {
		if (metadata.trim() !== "") {
			JSON.parse(metadata);
		}
	} catch (error) {
		event.preventDefault();
		displayErrorMessage("Metadata is not a valid JSON object", errorDiv);
		return false;
	}
	return true;
}

function validateTags(tags, errorDiv, event) {
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
			displayErrorMessage("tags must be strings in an array", errorDiv);
			return false;
		}
	} catch (error) {
		event.preventDefault();
		displayErrorMessage("tags must be a string array", errorDiv);
		return false;
	}

	return true;
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

// Form subsmission functions
// config parameters are: formId, url, alertDiv, modal
function submitCreateForm(config) {
	const form = document.getElementById(config.formId);
	form.addEventListener("submit", function (event) {
		event.preventDefault();
		const formData = new FormData(form);

		fetch(config.url, {
			method: "POST",
			body: formData,
		})
			.then(function (response) {
				switch (response.status) {
					case 409:
						showAlert("entity already exists!", config.alertDiv);
						break;
					case 400:
						showAlert("invalid file contents!", config.alertDiv);
						break;
					case 415:
						showAlert("invalid file type!", config.alertDiv);
						break;
					default:
						form.reset();
						config.modal.hide();
						window.location.reload();
				}
			})
			.catch((error) => {
				console.error("error submitting form: ", error);
			});
	});
}

function showAlert(errorMessage, alertDiv) {
	const alert = document.getElementById(alertDiv);
	alert.innerHTML = `
	<div class="alert alert-danger alert-dismissable fade show d-flex flex-row justify-content-between" role="alert">
	  <div>${errorMessage}</div>
	  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="close"></button>
	</div> `;
}

// Functions to make a row editable.

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
		removeErrorMessage(config.alertDiv);
	});
}

function submitUpdateForm(config) {
	fetch(config.url, {
		method: "POST",
		body: config.data,
		headers: {
			"Content-Type": "application/json",
		},
	}).then((response) => {
		switch (response.status) {
			case 409:
				showAlert("entity already exists!", config.alertDiv);
				break;
			default:
				window.location.reload();
		}
	});
}

function updateName(config) {
	const button = document.getElementById(config.button);

	button.addEventListener("click", function (event) {
		const updatedValue = config.cell.textContent.trim();
		if (validateName(updatedValue, config.alertDiv, event)) {
			const url = `/${config.entity}/${config.id}`;
			const data = JSON.stringify({ [config.field]: updatedValue });

			submitUpdateForm({
				url: url,
				data: data,
				alertDiv: config.alertDiv,
			});
		}
	});
}

function updateIdentity(config) {
	const button = document.getElementById(config.button);

	button.addEventListener("click", function (event) {
		const updatedValue = config.cell.textContent.trim();
		if (validateEmail(updatedValue, config.alertDiv, event)) {
			const url = `/${config.entity}/${config.id}/identity`;
			const data = JSON.stringify({ [config.field]: updatedValue });

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
		const updatedValue = config.cell.textContent.trim();
		if (validateMetadata(updatedValue, config.alertDiv, event)) {
			const url = `/${config.entity}/${config.id}`;
			const data = JSON.stringify({ [config.field]: JSON.parse(updatedValue) });

			submitUpdateForm({
				url: url,
				data: data,
				alertDiv: config.alertDiv,
			});
		}
	});
}

function updateTags(config) {
	const button = document.getElementById(config.button);

	button.addEventListener("click", function (event) {
		const updatedValue = config.cell.textContent.trim();
		if (validateTags(updatedValue, config.alertDiv, event)) {
			const url = `/${config.entity}/${config.id}/tags`;
			const data = JSON.stringify({ [config.field]: JSON.parse(updatedValue) });

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
		if (validatePassword(updatedValue, config.alertDiv, event)) {
			const url = `/${config.entity}/${config.id}/secret`;
			const data = JSON.stringify({ [config.field]: updatedValue });

			submitUpdateForm({
				url: url,
				data: data,
				alertDiv: config.alertDiv,
			});
		}
	});
}

function updateOwner(config) {
	const button = document.getElementById(config.button);

	button.addEventListener("click", function () {
		const updatedValue = config.cell.textContent.trim();
		const url = `/${config.entity}/${config.id}/owner`;
		const data = JSON.stringify({ [config.field]: updatedValue });

		submitUpdateForm({
			url: url,
			data: data,
			alertDiv: config.alertDiv,
		});
	});
}

function updateDescription(config) {
	const button = document.getElementById(config.button);

	button.addEventListener("click", function () {
		const updatedValue = config.cell.textContent.trim();
		const url = `/${config.entity}/${config.id}`;
		const data = JSON.stringify({ [config.field]: updatedValue });

		submitUpdateForm({
			url: url,
			data: data,
			alertDiv: config.alertDiv,
		});
	});
}

function attachEditRowListener(config) {
	for (const key in config.rows) {
		if (config.rows.hasOwnProperty(key)) {
			const cell = document.querySelector(`td[data-field="${key}"]`);
			const editBtn = cell.parentNode.querySelector(".edit-btn");
			const saveCancelBtn = cell.parentNode.querySelector(
				".save-cancel-buttons",
			);
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
			});
		}
	}
}

function fetchIndividualEntity(config) {
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
		var totalHeight =
			selectElement.querySelectorAll("option").length * singleOptionHeight;

		if (st > lastScrollTop) {
			currentScroll = st + selectBoxHeight;
			if (
				currentScroll + numOptionsBeforeLoad * singleOptionHeight >=
				totalHeight
			) {
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
