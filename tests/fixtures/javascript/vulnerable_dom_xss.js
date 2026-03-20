// Vulnerable: innerHTML assignment (DOM XSS)
function displayMessage(userInput) {
    document.getElementById("output").innerHTML = userInput;
}

// Vulnerable: setInterval with string argument
function pollServer(cmd) {
    setInterval(cmd, 5000);
}
