// apps/auth-service/src/auth-service.service.ts
import { Injectable } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  VerificationStatusResponse,
} from '@app/proto-definitions/auth';

@Injectable()
export class AuthService {
  constructor(private configService: ConfigService) {
    // Example: Log DB host on startup (ensure config is loaded)
    console.log(
      'Auth DB Host:',
      this.configService.get<string>('postgresql://localhost:5432/postgres'),
    );
  }

  async registerUser(data: RegisterRequest): Promise<RegisterResponse> {
    // --- TODO: ---
    // 1. Validate input (email format, password strength)
    // 2. Check if user already exists in DB
    // 3. Hash the password (use bcrypt)
    // 4. Create user record in PostgreSQL DB
    // 5. Potentially initiate verification flow (or mark as unverified)
    // 6. Return user ID and success message
    // --- Placeholder ---
    console.log(`Registering user ${data.email}... (Placeholder)`);
    if (!data.email || !data.password) {
      throw new RpcException('Email and password are required.'); // Example error
    }
    const userId = `user_${Date.now()}`; // Dummy user ID
    return {
      userId,
      message: 'Registration successful, verification required.',
    };
  }

  async loginUser(data: LoginRequest): Promise<LoginResponse> {
    // --- TODO: ---
    // 1. Find user by email in DB
    // 2. Compare provided password with hashed password in DB (use bcrypt.compare)
    // 3. Check verification status (maybe disallow login if not verified?)
    // 4. Generate JWT access token (include user_id, verification_status)
    // 5. Generate refresh token
    // 6. Potentially store refresh token securely
    // 7. Return tokens
    // --- Placeholder ---
    console.log(`Logging in user ${data.email}... (Placeholder)`);
    if (data.email === 'test@test.com' && data.password === 'password') {
      const dummyAccessToken = `jwt_access_${Date.now()}`;
      const dummyRefreshToken = `jwt_refresh_${Date.now()}`;
      return {
        accessToken: dummyAccessToken,
        refreshToken: dummyRefreshToken,
      };
    } else {
      throw new RpcException('Invalid credentials.'); // Example error
    }
  }

  async getVerificationStatus(
    userId: string,
  ): Promise<VerificationStatusResponse> {
    // --- TODO: ---
    // 1. Query PostgreSQL DB for the user's verification status
    // --- Placeholder ---
    console.log(`Checking status for ${userId}... (Placeholder)`);
    // Simulate finding a user
    const currentStatus = 'UNVERIFIED'; // Dummy status
    return { userId, status: currentStatus };
  }

  // Sample validateUser method for demonstration
  async validateUser(username: string, password: string): Promise<any> {
    // In a real app, you would query the database and compare hashed passwords
    if (username === 'test@test.com' && password === 'password') {
      return {
        userId: 'user_123',
        email: username,
        roles: ['user'],
        isVerified: true,
      };
    }
    return null;
  }
}
