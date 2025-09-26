package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"unsafe"
)

// CWE-78: Command injection
func commandInjection() {
	filename := os.Args[1]
	cmd := exec.Command("cat", filename) // VULNERABLE: command execution with user input
	output, _ := cmd.Output()
	fmt.Println(string(output))
}

// CWE-89: SQL injection
func sqlInjection() {
	userID := os.Args[1]
	query := "SELECT * FROM users WHERE id = " + userID // VULNERABLE: SQL injection
	fmt.Println(query)
	// db.Query(query) would execute the vulnerable query
}

// CWE-79: XSS via unsafe HTML template
func xssVulnerability() {
	userInput := "<script>alert('xss')</script>"
	tmpl := template.Must(template.New("page").Parse(`Hello {{.}}`))

	// VULNERABLE: bypassing auto-escaping
	safeHTML := template.HTML(userInput)
	tmpl.Execute(os.Stdout, safeHTML)

	// VULNERABLE: unsafe JavaScript
	jsCode := template.JS(userInput)
	fmt.Println(jsCode)
}

// CWE-327: Weak cryptographic algorithms
func weakCrypto() {
	data := []byte("sensitive data")

	// VULNERABLE: MD5 is cryptographically weak
	md5Hash := md5.Sum(data)
	fmt.Printf("MD5: %x\n", md5Hash)

	// VULNERABLE: SHA1 is cryptographically weak
	sha1Hash := sha1.Sum(data)
	fmt.Printf("SHA1: %x\n", sha1Hash)

	// VULNERABLE: DES encryption is weak
	desBlock, _ := des.NewCipher([]byte("12345678"))
	fmt.Println(desBlock)

	// VULNERABLE: RC4 is weak
	rc4Cipher, _ := rc4.NewCipher([]byte("key"))
	fmt.Println(rc4Cipher)
}

// CWE-330: Weak random number generation
func weakRandom() {
	// VULNERABLE: math/rand is not cryptographically secure
	token := rand.Intn(1000000)
	fmt.Printf("Token: %d\n", token)
}

// CWE-295: Insecure TLS configuration
func insecureTLS() {
	// VULNERABLE: disabling TLS certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	fmt.Println(client)
}

// CWE-22: Path traversal
func pathTraversal() {
	filename := os.Args[1]
	// VULNERABLE: path traversal via file operations
	content, _ := os.ReadFile("/var/data/" + filename)
	fmt.Println(string(content))
}

// CWE-276: Incorrect file permissions
func filePermissions() {
	filename := "sensitive.txt"
	// VULNERABLE: overly permissive file permissions
	file, _ := os.Create(filename) // Uses default permissions which may be too open
	defer file.Close()
	file.WriteString("sensitive data")
}

// CWE-798: Hardcoded credentials
func hardcodedCredentials() {
	// VULNERABLE: hardcoded password
	password := "admin123"
	apiKey := "sk-1234567890abcdef"
	fmt.Printf("Password: %s, API Key: %s\n", password, apiKey)
}

// CWE-200: Information exposure
func informationExposure() {
	// VULNERABLE: binding to all interfaces
	http.ListenAndServe(":8080", nil)
}

// CWE-119: Memory safety issue with unsafe package
func memorySafety() {
	// VULNERABLE: use of unsafe package
	data := []byte("hello")
	ptr := unsafe.Pointer(&data[0])
	fmt.Printf("Pointer: %v\n", ptr)
}

// CWE-252: Unchecked error
func uncheckedError() {
	filename := "nonexistent.txt"
	os.ReadFile(filename) // VULNERABLE: error not checked
}

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "test.txt")
	}

	commandInjection()
	sqlInjection()
	xssVulnerability()
	weakCrypto()
	weakRandom()
	insecureTLS()
	pathTraversal()
	filePermissions()
	hardcodedCredentials()
	informationExposure()
	memorySafety()
	uncheckedError()
}
