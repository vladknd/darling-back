import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import {Strategy} from 'passport-google-oauth20'
import { AuthService } from "../auth-service.service";
import { VerifyCallback } from "passport-google-oauth20";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    constructor(
        private readonly configService: ConfigService,
        private readonly authService: AuthService, // We inject AuthService to find/create users
      ) {
        super({
          clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
          clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
          callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'), // e.g., http://localhost:3000/api/auth/google/redirect
          scope: ['email', 'profile'],
        });
      }
    
      // This method is automatically called by Passport after it successfully
      // authenticates the user with Google. It provides us with the user's profile.
      async validate(
        accessToken: string,
        refreshToken: string,
        profile: any,
        done: VerifyCallback,
      ): Promise<any> {
        const { name, emails, photos } = profile;
        const user = {
          email: emails[0].value,
          firstName: name.givenName,
          lastName: name.familyName,
          picture: photos[0].value,
          accessToken, // The token from Google
        };
    
        // The 'done' callback is part of the Passport flow.
        // The first argument is for an error (if any), the second is for the user payload.
        done(null, user);
      }
}