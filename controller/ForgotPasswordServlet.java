package com.pfms.controller;

import com.pfms.util.DBConnection;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.*;
import java.util.UUID;
import java.time.LocalDateTime;

@WebServlet("/forgot-password")
public class ForgotPasswordServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        
        // 1. Generate a unique secure token
        String token = UUID.randomUUID().toString();
        
        // 2. Set expiry for 15 minutes from now
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(15);

        try (Connection conn = DBConnection.getConnection()) {
            // Check if user exists first
            PreparedStatement checkUser = conn.prepareStatement("SELECT id FROM users WHERE email = ?");
            checkUser.setString(1, email);
            ResultSet rs = checkUser.executeQuery();

            if (rs.next()) {
                // 3. Save the token to the database
                String sql = "REPLACE INTO password_resets (email, token, expiry_datetime) VALUES (?, ?, ?)";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, email);
                ps.setString(2, token);
                ps.setTimestamp(3, Timestamp.valueOf(expiry));
                ps.executeUpdate();

                // 4. Simulate sending an email (Printing to console)
                String resetLink = "http://localhost:8080" + request.getContextPath() + "/reset-password.html?token=" + token;
                System.out.println("DEBUG: Password Reset Link for " + email + " is: " + resetLink);

                response.sendRedirect("forgot-password.html?status=sent");
            } else {
                response.sendRedirect("forgot-password.html?error=notfound");
            }
        } catch (SQLException e) {
            e.printStackTrace();
            response.sendRedirect("forgot-password.html?error=db");
        }
    }
}