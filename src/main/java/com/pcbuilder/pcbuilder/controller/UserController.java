package com.pcbuilder.pcbuilder.controller;

import com.pcbuilder.pcbuilder.config.JwtUtil;
import com.pcbuilder.pcbuilder.model.User;
import com.pcbuilder.pcbuilder.repository.UserRepository;
import com.pcbuilder.pcbuilder.service.Email_service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api/users")
public class UserController {


    private Map<String, User> pendingUsers = new ConcurrentHashMap<>();
    @Autowired
    private UserRepository userRepo;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/register")
    public User registerUser(@RequestBody User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @GetMapping("/{username}")
    public User find_user(@PathVariable String username){
        User user = userRepo.findByUsername(username);
        if(user != null){
            user.setPassword(null);
        }
        return user;
    }

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login_user(@RequestBody User loginRequest) {
        User user = userRepo.findByUsername(loginRequest.getUsername());
        if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }

        String token = jwtUtil.generateToken(user.getUsername());
        return ResponseEntity.ok(Map.of("token", token));
    }

    @Autowired
    private Email_service emailService;
    @PostMapping("/request-otp")
    public ResponseEntity<?> requestOtp(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        User user = userRepo.findByEmail(email);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Email not registered");
        }

        // Generate random 6-digit OTP
        String otp = String.valueOf((int)(Math.random() * 900000) + 100000);

        // Save OTP & expiry (5 minutes from now)
        user.setOtp(otp);
        user.setOtpExpiry(System.currentTimeMillis() + (5 * 60 * 1000));
        userRepo.save(user);

        // For real project → send email/SMS
        System.out.println("Generated OTP for " + email + ": " + otp);
        emailService.sendEmail(email, "Your OTP Code", "Your OTP is: " + otp);

        return ResponseEntity.ok("OTP sent to registered email");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String otp = payload.get("otp");

        User user = userRepo.findByEmail(email);

        if (user == null || user.getOtp() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid request");
        }

        if (!otp.equals(user.getOtp())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP");
        }

        if (System.currentTimeMillis() > user.getOtpExpiry()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("OTP expired");
        }

        // Clear OTP so it cannot be reused
        user.setOtp(null);
        user.setOtpExpiry(null);
        userRepo.save(user);

        return ResponseEntity.ok("OTP verified, you can reset password now");
    }


    @PostMapping("/request-otp-register")
    public ResponseEntity<?> requestOtpForRegister(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String username = payload.get("username");

        if (userRepo.findByEmail(email) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already registered");
        }

        String otp = String.valueOf((int)(Math.random() * 900000) + 100000);

        // Temporarily store user without password
        User tempUser = new User(username, email, null);
        tempUser.setOtp(otp);
        tempUser.setOtpExpiry(System.currentTimeMillis() + (5 * 60 * 1000));
        pendingUsers.put(email, tempUser);

        emailService.sendEmail(email, "Verify your email", "Your OTP is: " + otp);

        return ResponseEntity.ok("OTP sent to email");
    }


    @PostMapping("/verify-otp-register")
    public ResponseEntity<?> verifyOtpRegister(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String otp = payload.get("otp");
        String password = payload.get("password"); // Now received here

        User tempUser = pendingUsers.get(email);

        if (tempUser == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No OTP request found for this email");
        }

        if (!otp.equals(tempUser.getOtp())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP");
        }

        if (System.currentTimeMillis() > tempUser.getOtpExpiry()) {
            pendingUsers.remove(email);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("OTP expired");
        }

        // Save verified user with password
        tempUser.setPassword(passwordEncoder.encode(password));
        userRepo.save(tempUser);
        pendingUsers.remove(email);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String newPassword = payload.get("password");

        User user = userRepo.findByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);

        return ResponseEntity.ok("Password reset successful");
    }




}
