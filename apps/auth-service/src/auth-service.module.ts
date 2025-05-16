import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthServiceController } from './auth-service.controller';
import { AuthService } from './auth-service.service';

@Module({
  imports: [ConfigModule.forRoot()],
  controllers: [AuthServiceController],
  providers: [AuthService],
})
export class AuthServiceModule {}
