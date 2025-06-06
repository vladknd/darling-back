// File: ./your-dating-app-backend/apps/auth-service/src/users/repositories/user-credential.repository.ts
// Purpose: Custom repository for UserCredential entity, encapsulating data access logic.
import { Injectable, Logger } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { UserCredential, VerificationStatus } from '../entities/user-credential.entity';
import { RegisterRequest } from '@app/proto-definitions/auth'; // Ensure path is correct

@Injectable()
export class UserCredentialRepository extends Repository<UserCredential> {
  private readonly logger = new Logger(UserCredentialRepository.name);

  constructor(private dataSource: DataSource) {
    // Initialize the base Repository with the UserCredential entity and an EntityManager instance.
    super(UserCredential, dataSource.createEntityManager());
  }

  async createUser(registerRequestDto: RegisterRequest, hashedPassword: string): Promise<UserCredential> {
    this.logger.debug(`Repository: Creating user credential for email: ${registerRequestDto.email}`);
    const newUser = this.create({ // 'this.create' comes from the base TypeORM Repository
      email: registerRequestDto.email,
      passwordHash: hashedPassword,
      verificationStatus: VerificationStatus.UNVERIFIED, // Default status upon registration
    });
    return this.save(newUser); // 'this.save' also comes from the base TypeORM Repository
  }

  async findByEmail(email: string): Promise<UserCredential | null> {
    this.logger.debug(`Repository: Finding user credential by email: ${email}`);
    return this.findOne({ where: { email } }); // 'this.findOne' from base Repository
  }

  async findById(id: string): Promise<UserCredential | null> {
    this.logger.debug(`Repository: Finding user credential by ID: ${id}`);
    return this.findOne({ where: { id } });
  }

  async updateUserVerificationStatus(user: UserCredential, status: VerificationStatus): Promise<UserCredential> {
    this.logger.log(`Repository: Updating verification status for user ID: ${user.id} to ${status}`);
    user.verificationStatus = status;
    return this.save(user); // Saves the updated user entity
  }
}
