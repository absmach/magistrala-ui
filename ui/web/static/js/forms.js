// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// config parameters are: formId, url, alertDiv, modal
export function submitCreateForm(config) {
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
          case 415:
            showAlert("invalid file type!", config.alertDiv);
            break;
          case 400:
            const errorMessage = response.headers.get("X-Error-Message");
            if (errorMessage) {
              showAlert(errorMessage, config.alertDiv);
            } else {
              showAlert("Bad Request", config.alertDiv);
            }
            break;
          default:
            form.reset();
            config.modal.hide();
            window.location.reload();
        }
      })
      .catch((error) => {
        console.error("error submitting form: ", error);
        showAlert(`error submitting form: ${error}`, config.alertDiv);
      });
  });
}

export function submitUpdateForm(config) {
  fetch(config.url, {
    method: "POST",
    body: JSON.stringify(config.data),
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((response) => {
      switch (response.status) {
        case 409:
          showAlert("entity already exists!", config.alertDiv);
          break;
        case 400:
          const errorMessage = response.headers.get("X-Error-Message");
          if (errorMessage) {
            if (config.field) {
              showAlert(errorMessage + ": " + config.field, config.alertDiv);
            } else {
              showAlert(errorMessage, config.alertDiv);
            }
          } else {
            showAlert("Bad Request", config.alertDiv);
          }
          break;
        default:
          window.location.reload();
      }
    })
    .catch((error) => {
      console.error("error submitting form: ", error);
      showAlert(`error submitting form: ${error}`, config.alertDiv);
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
