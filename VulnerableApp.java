// VulnerableApp.java - Sample code with security issues for CodeQL to detect

import java.sql.*;
import java.io.*;
import javax.servlet.http.*;


public class VulnerableApp {
    
    // VULNERABILITY 1: SQL Injection
    public void getUserData(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydb");
            Statement stmt = conn.createStatement();
            
            // BAD: Direct string concatenation - SQL Injection vulnerability
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while(rs.next()) {
                System.out.println(rs.getString("email"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 2: Command Injection
    public void pingServer(String serverAddress) {
        try {
            // BAD: User input directly in system command
            String command = "ping " + serverAddress;
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 3: Path Traversal
    public String readFile(String filename) {
        try {
            // BAD: No validation of file path - could read any file
            File file = new File("/var/www/uploads/" + filename);
            BufferedReader br = new BufferedReader(new FileReader(file));
            return br.readLine();
        } catch (IOException e) {
            return "Error reading file";
        }
    }
    
    // VULNERABILITY 4: Hard-coded credentials
    public void connectToDatabase() {
        String username = "admin";
        String password = "password123";  // BAD: Hard-coded password
        
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/mydb", 
                username, 
                password
            );
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 5: Weak cryptography
    public String hashPassword(String password) {
        try {
            // BAD: MD5 is cryptographically broken
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return new String(hash);
        } catch (Exception e) {
            return null;
        }
    }
    
    // VULNERABILITY 6: Cross-Site Scripting (XSS)
    public void displayUserComment(HttpServletRequest request, HttpServletResponse response) {
        try {
            String comment = request.getParameter("comment");
            PrintWriter out = response.getWriter();
            
            // BAD: Directly outputting user input without sanitization
            out.println("<div>" + comment + "</div>");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // VULNERABILITY 7: Insecure Random
    public String generateToken() {
        // BAD: Using Math.random() for security-sensitive operation
        return String.valueOf(Math.random() * 1000000);
    }
    
    // VULNERABILITY 8: NULL pointer dereference risk
    public int getStringLength(String str) {
        // BAD: No null check before calling method
        return str.length();
    }
    
    // SAFE EXAMPLE: Proper parameterized query
    public void getUserDataSafe(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydb");
            
            // GOOD: Using PreparedStatement prevents SQL injection
            String query = "SELECT * FROM users WHERE username = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            
            ResultSet rs = pstmt.executeQuery();
            while(rs.next()) {
                System.out.println(rs.getString("email"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
