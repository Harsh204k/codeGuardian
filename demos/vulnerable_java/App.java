import java.sql.*;
class App {
  public static void main(String[] args) throws Exception {
    String uid = args.length>0 ? args[0] : "1";
    Connection c = DriverManager.getConnection("jdbc:demo","u","p");
    Statement st = c.createStatement();
    ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id=" + uid); // JAVA-SQLI-001
    Runtime.getRuntime().exec("cmd /c " + uid); // JAVA-CMDI-001
  }
}
