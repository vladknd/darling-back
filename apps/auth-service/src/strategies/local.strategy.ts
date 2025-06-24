import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth-service.service';
import { LoginRequest } from '@app/proto-definitions/auth'; // Import LoginRequest interface

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super();
  }

  async validate(username: string, password: string): Promise<any> {
    // Construct the LoginRequest object, assuming 'username' is the email
    const loginPayload: LoginRequest = { email: username, password: password };

    // Call the login method from AuthService to validate credentials
    const userResult = await this.authService.login(loginPayload);

    // If the login method returns a user (meaning authentication was successful),
    // return a subset of the user data to be attached to the request object.
    // If login fails, authService.login is expected to throw an RpcException,
    // which will be caught and transformed into an UnauthorizedException by Passport.
    if (!userResult || !userResult.userId) {
      throw new UnauthorizedException();
    }

    return {
      userId: userResult.userId,
      // email: userResult.email,
      verificationStatus: userResult.verificationStatus,
    };
  }
}