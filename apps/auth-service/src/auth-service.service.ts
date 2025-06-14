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
import { JwtPayload } from './auth/interfaces/jwt-payload.interface';
import {
  AUTH_SERVICE_RABBITMQ_CLIENT, BCRYPT_SALT_ROUNDS_KEY,
  JWT_ACCESS_SECRET_KEY, JWT_REFRESH_SECRET_KEY, JWT_REFRESH_EXPIRES_IN_KEY,
  USER_REGISTERED_EVENT, USER_VERIFICATION_STATUS_UPDATED_EVENT
} from './auth/constants';

@Injectable()
export class AuthServiceService {
  private readonly logger = new Logger(AuthServiceService.name);

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
      } else {
        this.logger.warn(`Could not parse expiresIn string "${expiresInString}", using default.`);
      }
    } catch (e) {
      this.logger.warn(`Error parsing expiresIn string "${expiresInString}", using default: ${e.message}`);
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

    const refreshTokenExpiresInString = this.configService.get<string>(JWT_REFRESH_EXPIRES_IN_KEY);
    const expiresAt = this._getExpiryDate(refreshTokenExpiresInString);
    
    await this.usersService.storeRefreshToken(user, refreshToken, expiresAt);

    return { accessToken, refreshToken };
  }

  async register(data: RegisterRequest): Promise<RegisterResponse> {
    this.logger.log(`Attempting to register user: ${data.email}`);
    const existingUser = await this.usersService.findByEmail(data.email);
    if (existingUser) {
      this.logger.warn(`Registration attempt for existing email: ${data.email}`);
      throw new RpcException('User with this email already exists.');
    }

    const hashedPassword = await this._hashPassword(data.password);

    try {
      const newUser = await this.usersService.createUser(data, hashedPassword);
      
      const eventPayload = { userId: newUser.id, email: newUser.email, timestamp: new Date().toISOString() };
      this.eventEmitter.emit<string, any>(USER_REGISTERED_EVENT, eventPayload);
      this.logger.log(`User registered successfully: ${newUser.id}. Event '${USER_REGISTERED_EVENT}' emitted.`);
      
      return {
        userId: newUser.id,
        message: 'Registration successful. Please complete identity verification.',
      };
    } catch (error) {
      this.logger.error(`Error during registration for ${data.email}: ${error.message}`, error.stack);
      throw new RpcException('Registration failed due to an internal error.');
    }
  }

  async login(data: LoginRequest): Promise<LoginResponse> {
    this.logger.log(`Attempting login for user: ${data.email}`);
    const user = await this.usersService.findByEmail(data.email);
    if (!user) {
      this.logger.warn(`Login attempt for non-existent email: ${data.email}`);
      throw new RpcException('Invalid credentials.');
    }

    const isPasswordMatching = await bcrypt.compare(data.password, user.passwordHash);
    if (!isPasswordMatching) {
      this.logger.warn(`Invalid password attempt for email: ${data.email}`);
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
      this.logger.warn('Refresh token not found, already revoked, or DB expired.');
      throw new RpcException('Invalid or expired refresh token.');
    }

    try {
      const payloadFromRefreshToken = this.jwtService.verify<JwtPayload>(refreshToken, {
        secret: this.configService.get<string>(JWT_REFRESH_SECRET_KEY),
      });

      const user = await this.usersService.findById(payloadFromRefreshToken.userId);
      if (!user) {
        this.logger.error(`User ${payloadFromRefreshToken.userId} not found during token refresh. Revoking token.`);
        await this.usersService.revokeRefreshToken(storedToken);
        throw new RpcException('User associated with token no longer exists.');
      }

      await this.usersService.revokeRefreshToken(storedToken);
      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = await this._generateTokens(user);

      this.logger.log(`Access token refreshed for user: ${user.id}`);
      return { accessToken: newAccessToken, refreshToken: newRefreshToken, userId: user.id, verificationStatus: user.verificationStatus };
    } catch (error) {
      this.logger.error(`Refresh token validation failed or error during refresh: ${error.message}`, error.stack);
      if (storedToken && !storedToken.isRevoked) {
        await this.usersService.revokeRefreshToken(storedToken);
      }
      throw new RpcException('Invalid or expired refresh token.');
    }
  }

  async validateAccessToken(data: ValidateAccessTokenRequest): Promise<ValidateAccessTokenResponse> {
    this.logger.debug(`Validating access token.`);
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
      this.logger.warn(`Access token validation failed: ${error.message}`);
      return {
        userId: '', email: '', verificationStatus: '', isValid: false, roles: [], exp: 0, iat: 0,
      };
    }
  }

  async getVerificationStatus(request: UserIdRequest): Promise<VerificationStatusResponse> {
    const { userId } = request;
    this.logger.log(`Getting verification status for user: ${userId}`);
    const user = await this.usersService.findById(userId);
    if (!user) {
      this.logger.warn(`User not found for GetVerificationStatus: ${userId}`);
      throw new RpcException(`User with ID ${userId} not found.`);
    }
    return { userId: user.id, status: user.verificationStatus };
  }

  async processIdvWebhook(request: ProcessIdvWebhookRequest): Promise<ProcessIdvWebhookResponse> {
    const { userId, newStatus, idvProviderReference } = request;
    this.logger.log(`Processing IDV update for user ${userId} via gRPC. New status: ${newStatus}. Ref: ${idvProviderReference}.`);

    const validStatuses = Object.values(VerificationStatus) as string[];
    const upperNewStatus = newStatus.toUpperCase();

    if (!validStatuses.includes(upperNewStatus)) {
      this.logger.error(`Invalid verification status received from IDV processor: ${newStatus} for user ${userId}`);
      throw new RpcException(`Invalid verification status provided: ${newStatus}`);
    }
    const statusEnum = upperNewStatus as VerificationStatus;

    try {
      const updatedUser = await this.usersService.updateUserVerificationStatus(userId, statusEnum);
      
      const eventPayload = { 
        userId: updatedUser.id, 
        status: updatedUser.verificationStatus, 
        idvProviderReference,
        timestamp: new Date().toISOString() 
      };
      this.eventEmitter.emit<string, any>(USER_VERIFICATION_STATUS_UPDATED_EVENT, eventPayload);
      this.logger.log(`User ${userId} verification status updated to ${statusEnum}. Event '${USER_VERIFICATION_STATUS_UPDATED_EVENT}' emitted.`);
      
      return { success: true, message: 'Verification status updated successfully.' };
    } catch (error) {
      if (error instanceof NotFoundException) {
        this.logger.warn(`User ${userId} not found during IDV webhook processing: ${error.message}`);
        throw new RpcException(error.message);
      }
      this.logger.error(`Failed to update verification status for user ${userId} from IDV webhook: ${error.message}`, error.stack);
      throw new RpcException('Failed to update verification status due to an internal error.');
    }
  }
}
