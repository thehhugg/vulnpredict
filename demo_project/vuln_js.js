// Example vulnerable JavaScript code for VulnPredict demo

// 1. Use of eval with user input (code injection)
const userCode = prompt('Enter code:');
eval(userCode);

// 2. Unsanitized DOM assignment (XSS)
function setUserHTML(userInput) {
    document.getElementById('output').innerHTML = userInput;
}

// 3. Hardcoded API key (sensitive data)
const API_KEY = 'sk_test_1234567890abcdef';

// 4. Outdated dependency usage (simulated by requiring a known old package)
const xmlrpc = require('xmlrpc'); // Known for past vulnerabilities 