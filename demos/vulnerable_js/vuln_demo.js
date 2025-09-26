/**
 * Vulnerable JavaScript demo file for testing static analysis
 */

// CWE-95: Code injection via eval
function codeInjection() {
    var userInput = prompt("Enter code:");
    eval(userInput);  // VULNERABLE: eval with user input
    
    var func = new Function(userInput);  // VULNERABLE: Function constructor
    func();
}

// CWE-79: Cross-site scripting (XSS)
function xssVulnerability() {
    var name = document.getElementById('name').value;
    document.getElementById('output').innerHTML = "Hello " + name;  // VULNERABLE: XSS via innerHTML
    
    var msg = location.hash.substr(1);
    document.write(msg);  // VULNERABLE: document.write with untrusted data
}

// CWE-78: Command injection (Node.js)
function commandInjection() {
    const { exec } = require('child_process');
    var filename = process.argv[2];
    exec('cat ' + filename, (error, stdout, stderr) => {  // VULNERABLE: command injection
        console.log(stdout);
    });
}

// CWE-22: Path traversal (Node.js)
function pathTraversal() {
    const fs = require('fs');
    var filename = process.argv[2];
    fs.readFile('/var/data/' + filename, 'utf8', (err, data) => {  // VULNERABLE: path traversal
        console.log(data);
    });
}

// CWE-330: Weak random number generation
function weakRandom() {
    var token = Math.random().toString(36);  // VULNERABLE: Math.random is not cryptographically secure
    return token;
}

// CWE-502: Unsafe deserialization
function unsafeDeserialization() {
    var userData = prompt("Enter JSON data:");
    var obj = JSON.parse(userData);  // VULNERABLE: parsing untrusted JSON
    return obj;
}

// CWE-79: JavaScript URL scheme
function javascriptUrl() {
    var userUrl = prompt("Enter URL:");
    window.open("javascript:" + userUrl);  // VULNERABLE: JavaScript URL
    
    document.getElementById('link').href = "javascript:" + userUrl;  // VULNERABLE: JavaScript in href
}

// CWE-95: setTimeout/setInterval with strings
function timerInjection() {
    var userCode = prompt("Enter code:");
    setTimeout(userCode, 1000);  // VULNERABLE: setTimeout with string
    setInterval(userCode, 5000); // VULNERABLE: setInterval with string
}

// CWE-98: Dynamic require (Node.js)
function dynamicRequire() {
    var moduleName = process.argv[2];
    var module = require(moduleName);  // VULNERABLE: dynamic require
    return module;
}

// CWE-79: DOM manipulation vulnerabilities
function domManipulation() {
    var userInput = document.getElementById('userInput').value;
    
    // VULNERABLE: outerHTML concatenation
    document.getElementById('container').outerHTML = '<div>' + userInput + '</div>';
    
    // VULNERABLE: insertAdjacentHTML with user input
    document.body.insertAdjacentHTML('beforeend', userInput);
    
    // VULNERABLE: dynamic location.href
    location.href = 'http://example.com/' + userInput;
}

// Main execution
if (typeof window !== 'undefined') {
    // Browser environment
    codeInjection();
    xssVulnerability();
    javascriptUrl();
    timerInjection();
    domManipulation();
} else {
    // Node.js environment
    commandInjection();
    pathTraversal();
    dynamicRequire();
}

console.log(weakRandom());
unsafeDeserialization();