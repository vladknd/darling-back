// File: ./your-dating-app-backend/apps/auth-service/src/users/repositories/refresh-token.repository.ts
// Purpose: Custom repository for RefreshToken entity.
import { Injectable, Logger } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { RefreshToken } from '../entities/refresh-token.entity';
import { UserCredential } from '../entities/user-credential.entity';

@Injectable()
export class RefreshTokenRepository extends Repository<RefreshToken> {
  private readonly logger = new Logger(RefreshTokenRepository.name);

  constructor(private dataSource: DataSource) {
    super(RefreshToken, dataSource.createEntityManager());
  }

  async createAndSave(userCredential: UserCredential, token: string, expiresAt: Date): Promise<RefreshToken> {
    this.logger.debug(`Repository: Creating and saving refresh token for user ID: ${userCredential.id}`);
    const newRefreshToken = this.create({
      userCredential, // TypeORM will handle setting the userCredentialId foreign key
      token,
      expiresAt,
      isRevoked: false, // New tokens are not revoked
    });
    return this.save(newRefreshToken);
  }

  async findByToken(token: string): Promise<RefreshToken | null> {
    this.logger.debug(`Repository: Finding refresh token by token string.`);
    // Ensure you load the userCredential if you need to access it after finding the token
    // This is important because the RefreshToken entity has a ManyToOne with UserCredential
    return this.findOne({
      where: { token, isRevoked: false }, // Only find active, non-revoked tokens
      relations: ['userCredential'], // Eagerly load the related UserCredential
    });
  }

  async revoke(tokenInstance: RefreshToken): Promise<RefreshToken> {
    this.logger.log(`Repository: Revoking refresh token ID: ${tokenInstance.id}`);
    tokenInstance.isRevoked = true;
    return this.save(tokenInstance);
  }

  async revokeAllForUser(userCredentialId: string): Promise<void> {
    this.logger.log(`Repository: Revoking all active refresh tokens for user ID: ${userCredentialId}`);
    // This updates all non-revoked tokens for the specified user to be revoked.
    await this.update(
      { userCredentialId: userCredentialId, isRevoked: false }, // Condition: find tokens for this user that are not already revoked
      { isRevoked: true }, // Update: set isRevoked to true
    );
  }

  async findById(id: string): Promise<RefreshToken | null> {
    this.logger.debug(`Repository: Finding refresh token by ID: ${id}`);
    return this.findOne({ where: { id }, relations: ['userCredential'] });
  }
}
