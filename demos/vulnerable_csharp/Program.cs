using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Web;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApp
{
    class Program
    {
        // Hardcoded credentials - major security risk
        private const string DB_PASSWORD = "P@ssw0rd123!"; // CSHARP-HARDCRED-001
        private const string API_KEY = "sk-1234567890abcdef1234567890abcdef"; // CSHARP-HARDCRED-002
        private const string SECRET_KEY = "mySuperSecretKey123456789"; // CSHARP-HARDCRED-003

        static void Main(string[] args)
        {
            Console.WriteLine("=== Vulnerable C# Application Demo ===");

            // Get user input
            string userInput = args.Length > 0 ? args[0] : "admin";
            string userId = args.Length > 1 ? args[1] : "1";
            string fileName = args.Length > 2 ? args[2] : "config.txt";

            // SQL Injection vulnerability
            string connectionString = $"Server=localhost;Database=myapp;User Id=sa;Password={DB_PASSWORD};";
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                string sql = $"SELECT * FROM users WHERE id = {userId} AND name = '{userInput}'"; // CSHARP-SQLI-001
                SqlCommand cmd = new SqlCommand(sql, conn);
                SqlDataReader reader = cmd.ExecuteReader();
            }

            // Command injection vulnerability
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c dir {userInput}", // CSHARP-CMDI-001
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            Process.Start(psi);

            // Path traversal vulnerability
            string fullPath = Path.Combine("uploads", fileName); // CSHARP-PATH-001
            if (File.Exists(fullPath))
            {
                string content = File.ReadAllText(fullPath);
                Console.WriteLine($"File content: {content}");
            }

            // XSS vulnerability (simulated web context)
            string htmlOutput = $"<div>Welcome {userInput}</div>"; // CSHARP-XSS-001
            Console.WriteLine($"HTML Output: {htmlOutput}");

            // Weak encryption - using simple XOR
            string encrypted = EncryptPassword(userInput);
            Console.WriteLine($"Encrypted password: {encrypted}");

            // Insecure random number generation
            Random rand = new Random(); // CSHARP-WEAKRAND-001
            int sessionId = rand.Next(1000000);
            Console.WriteLine($"Session ID: {sessionId}");

            // Buffer overflow simulation with arrays
            int[] buffer = new int[10];
            for (int i = 0; i < 15; i++) // CSHARP-BUFFER-001
            {
                buffer[i] = i;
            }

            // Null reference exception potential
            string nullStr = null;
            if (userInput == "crash")
            {
                nullStr = null;
            }
            Console.WriteLine($"String length: {nullStr.Length}"); // CSHARP-NULLREF-001

            // Insecure deserialization (commented out to avoid actual execution)
            // System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            // using (FileStream fs = new FileStream("data.bin", FileMode.Open))
            // {
            //     object obj = formatter.Deserialize(fs); // CSHARP-DESER-001
            // }

            // Hardcoded API usage
            CallExternalAPI(API_KEY);

            Console.WriteLine("Application completed successfully");
        }

        // Weak encryption method
        static string EncryptPassword(string password)
        {
            StringBuilder encrypted = new StringBuilder();
            foreach (char c in password)
            {
                encrypted.Append((char)(c ^ 0x55)); // CSHARP-WEAKENC-001
            }
            return encrypted.ToString();
        }

        // Simulated API call with hardcoded credentials
        static void CallExternalAPI(string apiKey)
        {
            // In real code, this would make an HTTP request
            Console.WriteLine($"Calling API with key: {apiKey.Substring(0, 10)}...");
        }

        // Additional vulnerable method
        public static string ProcessUserInput(string input)
        {
            // SQL injection in a method
            string query = $"SELECT * FROM products WHERE name LIKE '%{input}%'"; // CSHARP-SQLI-002
            return query;
        }
    }
}
