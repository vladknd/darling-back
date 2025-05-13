import { Module } from '@nestjs/common';
import { ProfileServiceController } from './profile-service.controller';
import { ProfileServiceService } from './profile-service.service';

@Module({
  imports: [],
  controllers: [ProfileServiceController],
  providers: [ProfileServiceService],
})
export class ProfileServiceModule {}
