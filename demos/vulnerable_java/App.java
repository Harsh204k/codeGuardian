import java.nio.file.*;
import java.sql.*;
import java.util.*;

public class App {
    // Hardcoded credentials - SECURITY RISK
    private static final String DB_PASSWORD = "admin123!"; // JAVA-HARDCRED-001
    private static final String API_KEY = "sk-1234567890abcdef"; // JAVA-HARDCRED-002

    public static void main(String[] args) throws Exception {
        System.out.println("=== Vulnerable Java Application Demo ===");

        // Get user input (simulating web request parameters)
        String userId = args.length > 0 ? args[0] : "1";
        String userName = args.length > 1 ? args[1] : "admin";
        String filePath = args.length > 2 ? args[2] : "config.txt";

        // SQL Injection vulnerability - direct string concatenation
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/app", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id = " + userId + " AND name = '" + userName + "'"; // JAVA-SQLI-001
        ResultSet rs = stmt.executeQuery(sql);

        // Command Injection vulnerability
        String cmd = "ping " + userName; // JAVA-CMDI-001
        Process process = Runtime.getRuntime().exec(cmd);

        // Path Traversal vulnerability
        Path path = Paths.get("uploads", filePath); // JAVA-PATH-001
        if (Files.exists(path)) {
            String content = Files.readString(path);
            System.out.println("File content: " + content);
        }

        // Insecure random number generation
        Random rand = new Random(); // JAVA-WEAKRAND-001
        int sessionId = rand.nextInt(1000000);

        // Buffer overflow simulation with arrays
        int[] buffer = new int[10];
        for (int i = 0; i < 15; i++) { // JAVA-BUFFER-001
            buffer[i] = i;
        }

        // Null pointer dereference potential
        String nullStr = null;
        if (userName.equals("crash")) {
            nullStr = null;
        }
        System.out.println("String length: " + nullStr.length()); // JAVA-NULLPTR-001

        // Insecure deserialization (if implemented)
        // ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        // Object obj = ois.readObject(); // JAVA-DESER-001

        System.out.println("Application completed with session ID: " + sessionId);
    }

    // Additional vulnerable method
    public static String processUserData(String input) {
        // XSS vulnerability in string processing
        String html = "<div>Welcome " + input + "</div>"; // JAVA-XSS-001
        return html;
    }

    // Weak encryption example
    public static String encryptPassword(String password) {
        // Using simple XOR "encryption" - completely insecure
        StringBuilder encrypted = new StringBuilder();
        for (char c : password.toCharArray()) {
            encrypted.append((char)(c ^ 0x55)); // JAVA-WEAKENC-001
        }
        return encrypted.toString();
    }
}
