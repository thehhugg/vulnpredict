// Safe: no dangerous calls
function add(a, b) {
    return a + b;
}

function greet(name) {
    var message = "Hello, " + name;
    console.log(message);
    return message;
}

function validateInput(input) {
    var sanitized = encodeURIComponent(input);
    return sanitized;
}
