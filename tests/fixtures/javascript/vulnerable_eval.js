// Vulnerable: uses eval with user input
function processInput(userInput) {
    var result = eval(userInput);
    return result;
}

// Vulnerable: uses Function constructor
function createDynamic(code) {
    var fn = Function(code);
    return fn();
}

// Vulnerable: setTimeout with string argument
function delayedExec(cmd) {
    setTimeout(cmd, 1000);
}
