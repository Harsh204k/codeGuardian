using System;
using System.Data.SqlClient;
using System.Web;

namespace VulnerableApp
{
    class Program
    {
        static void Main(string[] args)
        {
            string userInput = Console.ReadLine();
            
            // SQL Injection vulnerability
            string sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
            
            // Command injection
            System.Diagnostics.Process.Start("cmd.exe", "/c " + userInput);
            
            // XSS vulnerability
            HttpContext.Current.Response.Write("<div>" + userInput + "</div>");
            
            // Path traversal
            System.IO.File.ReadAllText("uploads/" + userInput);
            
            // Hardcoded credentials
            string password = "admin123password";
            string apiKey = "sk-1234567890abcdef1234567890abcdef";
            
            Console.WriteLine("Vulnerable C# application");
        }
    }
}
