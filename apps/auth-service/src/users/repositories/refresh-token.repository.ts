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
      userCredential,
      token,
      expiresAt,
      isRevoked: false,
    });
    return this.save(newRefreshToken);
  }

  async findByToken(token: string): Promise<RefreshToken | null> {
    this.logger.debug(`Repository: Finding refresh token by token string.`);
    return this.findOne({
      where: { token, isRevoked: false },
      relations: ['userCredential'],
    });
  }

  async revoke(tokenInstance: RefreshToken): Promise<RefreshToken> {
    this.logger.log(`Repository: Revoking refresh token ID: ${tokenInstance.id}`);
    tokenInstance.isRevoked = true;
    return this.save(tokenInstance);
  }
}
