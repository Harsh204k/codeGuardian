// Java Test Dataset - Multiple Security Vulnerabilities
// File: VulnerableJavaApp.java

import java.sql.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
import java.security.MessageDigest;

public class VulnerableJavaApp extends HttpServlet {
    
    // VULNERABILITY 1: Hardcoded Database Credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-prod-1234567890";
    
    // VULNERABILITY 2: SQL Injection
    public void doLogin(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/users", "root", DB_PASSWORD);
                
            String query = "SELECT * FROM users WHERE username='" + username + 
                          "' AND password='" + password + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);  // SQL Injection vulnerability
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 3: Command Injection
    public void executeCommand(String userInput) {
        try {
            Runtime runtime = Runtime.getRuntime();
            Process process = runtime.exec("ping " + userInput);  // Command injection
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 4: Path Traversal
    public String readFile(String filename) {
        try {
            File file = new File("/uploads/" + filename);  // Path traversal vulnerability
            Scanner scanner = new Scanner(file);
            StringBuilder content = new StringBuilder();
            
            while (scanner.hasNextLine()) {
                content.append(scanner.nextLine());
            }
            scanner.close();
            return content.toString();
            
        } catch (IOException e) {
            return "Error reading file";
        }
    }
    
    // VULNERABILITY 5: Insecure Random Number Generation
    public String generateToken() {
        Random random = new Random();  // Weak randomness
        return String.valueOf(random.nextLong());
    }
    
    // VULNERABILITY 6: Weak Cryptography - MD5
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");  // Weak hash algorithm
            byte[] hashBytes = md.digest(password.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    // VULNERABILITY 7: XSS - Reflected
    public void doSearch(HttpServletRequest request, HttpServletResponse response) {
        String searchQuery = request.getParameter("q");
        
        try {
            PrintWriter out = response.getWriter();
            // XSS vulnerability - unescaped user input
            out.println("<h1>Search results for: " + searchQuery + "</h1>");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 8: Insecure Deserialization
    public Object deserializeData(byte[] data) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            return ois.readObject();  // Insecure deserialization
        } catch (Exception e) {
            return null;
        }
    }
    
    // VULNERABILITY 9: Information Disclosure
    public void logSensitiveData(String creditCard, String ssn) {
        System.out.println("Processing CC: " + creditCard + ", SSN: " + ssn);  // Logging sensitive data
    }
}
