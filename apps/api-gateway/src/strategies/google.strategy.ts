import { Injectable, UnauthorizedException, Logger, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { AUTH_PACKAGE_NAME } from '@app/proto-definitions'; // For gRPC package name
import { lastValueFrom } from 'rxjs'; // To convert Observable to Promise

// Define a token for the Auth Service gRPC client in API Gateway
export const AUTH_SERVICE_GRPC = 'AUTH_SERVICE_GRPC';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    @Inject(AUTH_SERVICE_GRPC) private readonly authServiceClient: ClientProxy,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
    this.logger.log('GoogleStrategy initialized.');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    this.logger.debug(`Google profile received for: ${profile.emails[0].value}`);
    const { name, emails, photos } = profile;
    const email = emails[0].value;
    const googleId = profile.id; // Google's unique ID for the user

    // TODO: The auth-service needs a new gRPC method (e.g., 'SocialLogin')
    // that takes social profile data and returns application-specific tokens.
    // For now, we'll simulate the expected call.

    try {
      // Simulate a call to a new gRPC method in auth-service
      // This method would handle:
      // 1. Checking if a user with this Google ID or email already exists.
      // 2. If not, creating a new user.
      // 3. Associating the Google ID with the user.
      // 4. Issuing your application's JWT access and refresh tokens.
      const socialLoginResponse = await lastValueFrom(
        this.authServiceClient.send('SocialLogin', {
          email: email,
          firstName: name.givenName,
          lastName: name.familyName,
          googleId: googleId,
          profilePicture: photos[0].value,
        }),
      );

      if (!socialLoginResponse || !socialLoginResponse.userId) {
        throw new UnauthorizedException('Failed to process Google login in auth service.');
      }

      // The socialLoginResponse would contain accessToken, refreshToken, userId, etc.
      // Return the relevant user information for Passport to attach to req.user
      done(null, {
        userId: socialLoginResponse.userId,
        email: socialLoginResponse.email,
        verificationStatus: socialLoginResponse.verificationStatus,
        accessToken: socialLoginResponse.accessToken,
        refreshToken: socialLoginResponse.refreshToken,
      });

    } catch (error) {
      this.logger.error(`Error during Google authentication: ${error.message}`, error.stack);
      done(new RpcException(`Google authentication failed: ${error.message}`), false);
    }
  }
}