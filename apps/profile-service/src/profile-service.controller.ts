import { Controller, Get } from '@nestjs/common';
import { ProfileServiceService } from './profile-service.service';

@Controller()
export class ProfileServiceController {
  constructor(private readonly profileServiceService: ProfileServiceService) {}

  @Get()
  getHello(): string {
    return this.profileServiceService.getHello();
  }
}
