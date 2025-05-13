import { Injectable } from '@nestjs/common';

@Injectable()
export class ProfileServiceService {
  getHello(): string {
    return 'Hello World!';
  }
}
