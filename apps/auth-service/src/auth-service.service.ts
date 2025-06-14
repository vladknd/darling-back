import { Inject, Injectable, Logger } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  ValidateAccessTokenRequest,
  ValidateAccessTokenResponse,
  RefreshAccessTokenRequest,
  VerificationStatusResponse,
  ProcessIdvWebhookRequest,
  ProcessIdvWebhookResponse,
} from '@app/proto-definitions/auth';
import { UsersService } from './users/users.service';
import {
  BCRYPT_SALT_ROUNDS_KEY,
  JWT_REFRESH_EXPIRES_IN_KEY,
  JWT_REFRESH_SECRET_KEY,
} from './constants';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { UserCredential, VerificationStatus } from './users/entities/user-credential.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<Omit<UserCredential, 'passwordHash'> | null> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await bcrypt.compare(pass, user.passwordHash))) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { passwordHash, ...result } = user;
      return result;
    }
    return null;
  }
  
  async registerUser(data: RegisterRequest): Promise<RegisterResponse> {
    this.logger.log(`Registering user ${data.email}...`);

    const existingUser = await this.usersService.findByEmail(data.email);
    if (existingUser) {
      throw new RpcException('User with this email already exists.');
    }

    const saltRounds = this.configService.get<number>(BCRYPT_SALT_ROUNDS_KEY);
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);

    const newUser = await this.usersService.createUser(data, hashedPassword);

    return {
      userId: newUser.id,
      message: 'Registration successful, verification required.',
    };
  }

  async loginUser(data: LoginRequest): Promise<LoginResponse> {
    this.logger.log(`Attempting login for ${data.email}...`);
    const user = await this.usersService.findByEmail(data.email);

    if (!user) {
      throw new RpcException('Invalid credentials.');
    }

    const isPasswordMatching = await bcrypt.compare(data.password, user.passwordHash);
    if (!isPasswordMatching) {
      throw new RpcException('Invalid credentials.');
    }

    const accessToken = await this.createAccessToken(user);
    const refreshToken = await this.createRefreshToken(user);

    return {
      userId: user.id,
      verificationStatus: user.verificationStatus,
      accessToken,
      refreshToken,
    };
  }

  async refreshAccessToken(data: RefreshAccessTokenRequest): Promise<LoginResponse> {
    this.logger.log(`Refreshing access token.`);
    const { refreshToken } = data;

    const refreshTokenSecret = this.configService.get<string>(JWT_REFRESH_SECRET_KEY);
    try {
      const payload: JwtPayload = this.jwtService.verify(refreshToken, { secret: refreshTokenSecret });

      const user = await this.usersService.findById(payload.userId);
      if (!user) {
        throw new RpcException('User not found.');
      }

      const storedToken = await this.usersService.findActiveRefreshToken(refreshToken);
      if (!storedToken) {
          throw new RpcException('Refresh token is invalid or has been revoked.');
      }

      const newAccessToken = await this.createAccessToken(user);
      const newRefreshToken = await this.createRefreshToken(user);

      await this.usersService.revokeRefreshToken(storedToken);

      return {
        userId: user.id,
        verificationStatus: user.verificationStatus,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      this.logger.error('Refresh token validation failed', error);
      throw new RpcException('Invalid or expired refresh token.');
    }
  }

  async validateAccessToken(data: ValidateAccessTokenRequest): Promise<ValidateAccessTokenResponse> {
    this.logger.log(`Validating access token...`);
    try {
      const payload: JwtPayload = await this.jwtService.verifyAsync(data.accessToken, {
        secret: this.configService.get<string>(JWT_ACCESS_SECRET_KEY),
      });
      const user = await this.usersService.findById(payload.userId);
      if (!user) {
          return { isValid: false, userId: '', email: '', verificationStatus: '', roles: [], exp: 0, iat: 0 };
      }
      return {
        isValid: true,
        userId: user.id,
        email: user.email,
        verificationStatus: user.verificationStatus,
        roles: payload.roles || [],
        exp: payload.exp,
        iat: payload.iat,
      };
    } catch (e) {
      this.logger.warn(`Access token validation failed: ${e.message}`);
      return { isValid: false, userId: '', email: '', verificationStatus: '', roles: [], exp: 0, iat: 0 };
    }
  }

  async getVerificationStatus(data: { userId: string }): Promise<VerificationStatusResponse> {
    this.logger.log(`Checking status for ${data.userId}...`);
    const user = await this.usersService.findById(data.userId);
    if (!user) {
      throw new RpcException('User not found.');
    }
    return { userId: user.id, status: user.verificationStatus };
  }

  async processIdvWebhook(data: ProcessIdvWebhookRequest): Promise<ProcessIdvWebhookResponse> {
    this.logger.log(`Processing IDV Webhook for user ${data.userId} with new status ${data.newStatus}`);
    try {
        const newStatus = data.newStatus.toUpperCase() as VerificationStatus;
        if (!Object.values(VerificationStatus).includes(newStatus)) {
            throw new Error(`Invalid verification status provided: ${data.newStatus}`);
        }
        await this.usersService.updateUserVerificationStatus(data.userId, newStatus);
        return { success: true, message: 'Status updated successfully.' };
    } catch(error) {
        this.logger.error(`Failed to process IDV webhook for user ${data.userId}`, error);
        return { success: false, message: error.message };
    }
  }
  
  private async createAccessToken(user: UserCredential): Promise<string> {
    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
      verificationStatus: user.verificationStatus,
      roles: ['user'], // You can expand this with a roles system
    };
    return this.jwtService.sign(payload);
  }

  private async createRefreshToken(user: UserCredential): Promise<string> {
    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
      verificationStatus: user.verificationStatus,
    };
    const secret = this.configService.get<string>(JWT_REFRESH_SECRET_KEY);
    const expiresIn = this.configService.get<string>(JWT_REFRESH_EXPIRES_IN_KEY);

    const refreshToken = this.jwtService.sign(payload, { secret, expiresIn });
    
    const decoded: any = this.jwtService.decode(refreshToken);
    const expiresAt = new Date(decoded.exp * 1000);

    await this.usersService.storeRefreshToken(user, refreshToken, expiresAt);

    return refreshToken;
  }
}