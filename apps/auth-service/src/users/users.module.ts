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
    TypeOrmModule.forFeature([UserCredential, RefreshToken]),
  ],
  providers: [
    UsersService,
    UserCredentialRepository,
    RefreshTokenRepository,
  ],
  exports: [UsersService], // Export UsersService so AuthServiceService can inject and use it
})
export class UsersModule {}

