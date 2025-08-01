package com.pcbuilder.pcbuilder.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import com.pcbuilder.pcbuilder.repository.UserRepository;
import com.pcbuilder.pcbuilder.model.User;

import java.util.List;

@Component
public class OtpCleanupTask {

    private final UserRepository userRepo;

    public OtpCleanupTask(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    // Run every 30 minutes
    @Scheduled(fixedRate = 30 * 60 * 1000)  // 30 min in ms
    public void clearExpiredOtps() {
        long now = System.currentTimeMillis();
        List<User> users = userRepo.findAll();

        for (User user : users) {
            if (user.getOtpExpiry() != null && user.getOtpExpiry() < now) {
                user.setOtp(null);
                user.setOtpExpiry(null);
                userRepo.save(user);
            }
        }

        System.out.println("Auto-cleanup: Expired OTPs removed.");
    }
}
