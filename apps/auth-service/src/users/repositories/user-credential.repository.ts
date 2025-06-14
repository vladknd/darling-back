// File: ./your-dating-app-backend/apps/auth-service/src/users/repositories/user-credential.repository.ts
// Purpose: Custom repository for UserCredential entity.
import { Injectable, Logger } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { UserCredential, VerificationStatus } from '../entities/user-credential.entity';
import { RegisterRequest } from '@app/proto-definitions/auth';

@Injectable()
export class UserCredentialRepository extends Repository<UserCredential> {
  private readonly logger = new Logger(UserCredentialRepository.name);

  constructor(private dataSource: DataSource) {
    super(UserCredential, dataSource.createEntityManager());
  }

  async createUser(registerRequestDto: RegisterRequest, hashedPassword: string): Promise<UserCredential> {
    this.logger.debug(`Repository: Creating user credential for email: ${registerRequestDto.email}`);
    const newUser = this.create({
      email: registerRequestDto.email,
      passwordHash: hashedPassword,
      verificationStatus: VerificationStatus.UNVERIFIED,
    });
    return this.save(newUser);
  }

  async findByEmail(email: string): Promise<UserCredential | null> {
    this.logger.debug(`Repository: Finding user credential by email: ${email}`);
    return this.findOne({ where: { email } });
  }

  async findById(id: string): Promise<UserCredential | null> {
    this.logger.debug(`Repository: Finding user credential by ID: ${id}`);
    return this.findOne({ where: { id } });
  }

  async updateUserVerificationStatus(user: UserCredential, status: VerificationStatus): Promise<UserCredential> {
    this.logger.log(`Repository: Updating verification status for user ID: ${user.id} to ${status}`);
    user.verificationStatus = status;
    return this.save(user);
  }
}
