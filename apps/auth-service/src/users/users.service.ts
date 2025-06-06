// File: ./your-dating-app-backend/apps/auth-service/src/users/users.service.ts
// Purpose: Service layer for user data operations, interacting with repositories.
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { UserCredentialRepository } from './repositories/user-credential.repository';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { UserCredential, VerificationStatus } from './entities/user-credential.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { RegisterRequest } from '@app/proto-definitions/auth'; // Ensure path is correct

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private readonly userCredentialRepository: UserCredentialRepository,
    private readonly refreshTokenRepository: RefreshTokenRepository,
  ) {}

  async createUser(registerRequestDto: RegisterRequest, hashedPassword: string): Promise<UserCredential> {
    this.logger.debug(`Creating user credential for email: ${registerRequestDto.email}`);
    return this.userCredentialRepository.createUser(registerRequestDto, hashedPassword);
  }

  async findByEmail(email: string): Promise<UserCredential | null> {
    this.logger.debug(`Finding user credential by email: ${email}`);
    return this.userCredentialRepository.findByEmail(email);
  }

  async findById(id: string): Promise<UserCredential | null> {
    this.logger.debug(`Finding user credential by ID: ${id}`);
    const user = await this.userCredentialRepository.findById(id);
    // It's often better for the calling service (AuthServiceService) to decide if NotFoundException is appropriate.
    // For example, during login, if user is not found, we throw "Invalid credentials", not "User not found".
    // if (!user) {
    //   throw new NotFoundException(`UserCredential with ID ${id} not found.`);
    // }
    return user;
  }

  async updateUserVerificationStatus(userId: string, status: VerificationStatus): Promise<UserCredential> {
    this.logger.log(`Updating verification status for user ID: ${userId} to ${status}`);
    const user = await this.findById(userId); // Use this.findById to ensure consistent user fetching
    if (!user) {
      this.logger.warn(`Attempted to update verification status for non-existent user ID: ${userId}`);
      throw new NotFoundException(`UserCredential with ID ${userId} not found for verification update.`);
    }
    return this.userCredentialRepository.updateUserVerificationStatus(user, status);
  }

  async storeRefreshToken(userCredential: UserCredential, token: string, expiresAt: Date): Promise<RefreshToken> {
    this.logger.debug(`Storing refresh token for user ID: ${userCredential.id}`);
    // Optional: Implement logic to limit number of active refresh tokens per user
    // Or, as done in RefreshTokenRepository, revoke all other active tokens for this user.
    // await this.refreshTokenRepository.revokeAllForUser(userCredential.id);
    return this.refreshTokenRepository.createAndSave(userCredential, token, expiresAt);
  }

  async findActiveRefreshToken(token: string): Promise<RefreshToken | null> {
    this.logger.debug(`Finding active refresh token`);
    // The repository method findByToken already checks for isRevoked: false and includes userCredential
    const refreshToken = await this.refreshTokenRepository.findByToken(token);
    if (refreshToken && refreshToken.expiresAt < new Date()) {
        this.logger.warn(`Found refresh token but it has expired in DB: ${token.substring(0,10)}...`);
        await this.revokeRefreshToken(refreshToken); // Proactively revoke if DB says expired
        return null;
    }
    return refreshToken;
  }

  async revokeRefreshToken(tokenInstance: RefreshToken): Promise<RefreshToken> {
    this.logger.log(`Revoking refresh token ID: ${tokenInstance.id}`);
    return this.refreshTokenRepository.revoke(tokenInstance);
  }
}
