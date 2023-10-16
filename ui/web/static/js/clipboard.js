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
