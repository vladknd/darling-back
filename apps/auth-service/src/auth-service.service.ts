// File: ./your-dating-app-backend/apps/auth-service/src/auth-service.service.ts
// Purpose: Core business logic for authentication.
import { Injectable, Inject, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { ClientProxy } from '@nestjs/microservices';

import { UsersService } from './users/users.service';
import { UserCredential, VerificationStatus } from './users/entities/user-credential.entity';
import {
  LoginRequest, LoginResponse,
  RegisterRequest, RegisterResponse,
  RefreshAccessTokenRequest,
  ValidateAccessTokenRequest, ValidateAccessTokenResponse,
  VerificationStatusResponse,
  ProcessIdvWebhookRequest, ProcessIdvWebhookResponse,
  UserIdRequest,
} from '@app/proto-definitions/auth';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import {
  AUTH_SERVICE_RABBITMQ_CLIENT, BCRYPT_SALT_ROUNDS_KEY,
  JWT_ACCESS_SECRET_KEY, JWT_REFRESH_SECRET_KEY, JWT_REFRESH_EXPIRES_IN_KEY,
  USER_REGISTERED_EVENT, USER_VERIFICATION_STATUS_UPDATED_EVENT
} from './constants';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @Inject(AUTH_SERVICE_RABBITMQ_CLIENT) private readonly eventEmitter: ClientProxy,
  ) {}

  private async _hashPassword(password: string): Promise<string> {
    const saltRounds = this.configService.get<number>(BCRYPT_SALT_ROUNDS_KEY);
    return bcrypt.hash(password, saltRounds);
  }

  // --- FIX ---
  // Helper function to calculate expiry date from a string like "7d" or "15m"
  private _getExpiryDate(expiresInString: string): Date {
    let expiresInMs = 7 * 24 * 60 * 60 * 1000; // Default 7 days if parsing fails
    try {
      if (expiresInString.endsWith('d')) {
        expiresInMs = parseInt(expiresInString.slice(0, -1)) * 24 * 60 * 60 * 1000;
      } else if (expiresInString.endsWith('h')) {
        expiresInMs = parseInt(expiresInString.slice(0, -1)) * 60 * 60 * 1000;
      } else if (expiresInString.endsWith('m')) {
        expiresInMs = parseInt(expiresInString.slice(0, -1)) * 60 * 1000;
      } else if (expiresInString.endsWith('s')) {
        expiresInMs = parseInt(expiresInString.slice(0, -1)) * 1000;
      } else if (!isNaN(Number(expiresInString))) {
        expiresInMs = Number(expiresInString);
      }
    } catch (e) {
      this.logger.warn(`Error parsing expiresIn string "${expiresInString}", using default.`);
    }
    return new Date(Date.now() + expiresInMs);
  }

  private async _generateTokens(user: UserCredential): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
      verificationStatus: user.verificationStatus,
    };
    const accessToken = this.jwtService.sign(payload);

    const refreshTokenPayload: JwtPayload = { ...payload };
    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      secret: this.configService.get<string>(JWT_REFRESH_SECRET_KEY),
      expiresIn: this.configService.get<string>(JWT_REFRESH_EXPIRES_IN_KEY),
    });

    // --- FIX ---
    // Instead of decoding, we calculate the expiry date based on the configuration string
    const expiresAt = this._getExpiryDate(this.configService.get<string>(JWT_REFRESH_EXPIRES_IN_KEY));
    
    await this.usersService.storeRefreshToken(user, refreshToken, expiresAt);

    return { accessToken, refreshToken };
  }

  async register(data: RegisterRequest): Promise<RegisterResponse> {
    this.logger.log(`Attempting to register user: ${data.email}`);
    const existingUser = await this.usersService.findByEmail(data.email);
    if (existingUser) {
      throw new RpcException('User with this email already exists.');
    }
    const hashedPassword = await this._hashPassword(data.password);
    const newUser = await this.usersService.createUser(data, hashedPassword);
    
    const eventPayload = { userId: newUser.id, email: newUser.email, timestamp: new Date().toISOString() };
    this.eventEmitter.emit<string, any>(USER_REGISTERED_EVENT, eventPayload);
    this.logger.log(`User registered successfully: ${newUser.id}. Event '${USER_REGISTERED_EVENT}' emitted.`);
    
    return {
      userId: newUser.id,
      message: 'Registration successful. Please complete identity verification.',
    };
  }

  async login(data: LoginRequest): Promise<LoginResponse> {
    this.logger.log(`Attempting login for user: ${data.email}`);
    const user = await this.usersService.findByEmail(data.email);
    if (!user) {
      throw new RpcException('Invalid credentials.');
    }
    const isPasswordMatching = await bcrypt.compare(data.password, user.passwordHash);
    if (!isPasswordMatching) {
      throw new RpcException('Invalid credentials.');
    }
    const { accessToken, refreshToken } = await this._generateTokens(user);
    this.logger.log(`User logged in successfully: ${user.id}`);
    return { accessToken, refreshToken, userId: user.id, verificationStatus: user.verificationStatus };
  }

  async refreshAccessToken(data: RefreshAccessTokenRequest): Promise<LoginResponse> {
    const { refreshToken } = data;
    this.logger.log(`Attempting to refresh access token.`);
    const storedToken = await this.usersService.findActiveRefreshToken(refreshToken);
    if (!storedToken) {
      throw new RpcException('Invalid or expired refresh token.');
    }
    try {
      const payloadFromRefreshToken = this.jwtService.verify<JwtPayload>(refreshToken, {
        secret: this.configService.get<string>(JWT_REFRESH_SECRET_KEY),
      });
      const user = await this.usersService.findById(payloadFromRefreshToken.userId);
      if (!user) {
        await this.usersService.revokeRefreshToken(storedToken);
        throw new RpcException('User associated with token no longer exists.');
      }
      await this.usersService.revokeRefreshToken(storedToken);
      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = await this._generateTokens(user);
      this.logger.log(`Access token refreshed for user: ${user.id}`);
      return { accessToken: newAccessToken, refreshToken: newRefreshToken, userId: user.id, verificationStatus: user.verificationStatus };
    } catch (error) {
      this.logger.error(`Refresh token validation failed: ${error.message}`);
      if (storedToken && !storedToken.isRevoked) {
        await this.usersService.revokeRefreshToken(storedToken);
      }
      throw new RpcException('Invalid or expired refresh token.');
    }
  }

  // ... (validateAccessToken, getVerificationStatus, processIdvWebhook methods remain the same) ...
  async validateAccessToken(data: ValidateAccessTokenRequest): Promise<ValidateAccessTokenResponse> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(data.accessToken);
      return {
        userId: payload.userId,
        email: payload.email,
        verificationStatus: payload.verificationStatus,
        isValid: true,
        roles: payload.roles || [],
        exp: payload.exp || 0,
        iat: payload.iat || 0,
      };
    } catch (error) {
      return { userId: '', email: '', verificationStatus: '', isValid: false, roles: [], exp: 0, iat: 0 };
    }
  }

  async getVerificationStatus(request: UserIdRequest): Promise<VerificationStatusResponse> {
    const user = await this.usersService.findById(request.userId);
    if (!user) {
      throw new RpcException(`User with ID ${request.userId} not found.`);
    }
    return { userId: user.id, status: user.verificationStatus };
  }

  async processIdvWebhook(request: ProcessIdvWebhookRequest): Promise<ProcessIdvWebhookResponse> {
    const { userId, newStatus, idvProviderReference } = request;
    const validStatuses = Object.values(VerificationStatus) as string[];
    const upperNewStatus = newStatus.toUpperCase();
    if (!validStatuses.includes(upperNewStatus)) {
      throw new RpcException(`Invalid verification status provided: ${newStatus}`);
    }
    const statusEnum = upperNewStatus as VerificationStatus;
    const updatedUser = await this.usersService.updateUserVerificationStatus(userId, statusEnum);
    this.eventEmitter.emit<string, any>(USER_VERIFICATION_STATUS_UPDATED_EVENT, { userId: updatedUser.id, status: updatedUser.verificationStatus, idvProviderReference, timestamp: new Date().toISOString() });
    return { success: true, message: 'Verification status updated successfully.' };
  }
}
