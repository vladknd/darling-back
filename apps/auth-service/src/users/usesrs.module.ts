// File: ./your-dating-app-backend/apps/auth-service/src/users/users.module.ts
// Purpose: Module for user data access layer (UserCredential, RefreshToken).
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserCredential } from './entities/user-credential.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { UsersService } from './users.service';
import { UserCredentialRepository } from './repositories/user-credential.repository';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';

@Module({
  imports: [
    // This makes the standard TypeORM Repository<UserCredential> and Repository<RefreshToken>
    // available for injection if UserCredentialRepository and RefreshTokenRepository
    // were not extending them or if you wanted to inject the base repository directly.
    // Since our custom repositories extend TypeORM's Repository and are provided below,
    // this forFeature call primarily ensures TypeORM is aware of these entities.
    TypeOrmModule.forFeature([UserCredential, RefreshToken]),
  ],
  providers: [
    UsersService,
    UserCredentialRepository, // Provide your custom repository
    RefreshTokenRepository,   // Provide your custom repository
  ],
  exports: [UsersService], // Export UsersService so AuthServiceService can inject and use it
})
export class UsersModule {}
