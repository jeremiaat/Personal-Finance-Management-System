package com.pfms.controller;

import com.pfms.util.DBConnection;
import org.mindrot.jbcrypt.BCrypt;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.*;

@WebServlet("/reset-password")
public class ResetPasswordServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String token = request.getParameter("token");
        String newPassword = request.getParameter("password");

        try (Connection conn = DBConnection.getConnection()) {
            // 1. Check if token is valid and not expired
            String checkSql = "SELECT email FROM password_resets WHERE token = ? AND expiry_datetime > NOW()";
            PreparedStatement psCheck = conn.prepareStatement(checkSql);
            psCheck.setString(1, token);
            ResultSet rs = psCheck.executeQuery();

            if (rs.next()) {
                String email = rs.getString("email");

                // 2. Hash the new password
                String hashedPw = BCrypt.hashpw(newPassword, BCrypt.gensalt());

                // 3. Update the users table
                PreparedStatement psUpdate = conn.prepareStatement("UPDATE users SET password = ? WHERE email = ?");
                psUpdate.setString(1, hashedPw);
                psUpdate.setString(2, email);
                psUpdate.executeUpdate();

                // 4. Delete the used token
                PreparedStatement psDel = conn.prepareStatement("DELETE FROM password_resets WHERE token = ?");
                psDel.setString(1, token);
                psDel.executeUpdate();

                response.sendRedirect("index.html?status=reset_success");
            } else {
                response.sendRedirect("reset-password.html?error=invalid_or_expired&token=" + token);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}