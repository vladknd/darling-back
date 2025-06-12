// File: ./your-dating-app-backend/apps/auth-service/src/auth/strategies/jwt.strategy.ts
// Purpose: Passport strategy for validating JWTs.
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, StrategyOptions } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../interfaces/jwt-payload.interface'; // Ensure path is correct
import { UserCredentialRepository } from '../users/repositories/user-credential.repository'; // To verify user existence from DB
import { JWT_ACCESS_SECRET_KEY } from '../constants'; // Ensure path is correct
import { UsersService } from '../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') { // Naming the strategy 'jwt'
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService, // Inject UsersService to fetch up-to-date user info
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Standard extraction from 'Bearer <token>' header
      ignoreExpiration: false, // Passport-jwt will automatically handle expired tokens
      secretOrKey: configService.get<string>(JWT_ACCESS_SECRET_KEY),
      // passReqToCallback: false, // Omit or leave commented out
    });
    this.logger.log('JwtStrategy initialized. Will use JWT_ACCESS_SECRET for token verification.');
  }

  /**
   * This method is called by Passport after it has successfully verified the JWT's signature
   * and that it has not expired. The 'payload' argument is the decoded JSON object from the JWT.
   * The value returned from this method will be attached to the request object (e.g., req.user for HTTP,
   * or made available in the gRPC context if a guard uses this strategy for gRPC calls).
   */
  async validate(payload: JwtPayload): Promise<JwtPayload> { // Return type should match what you want on req.user
    this.logger.debug(`Validating JWT payload for userId: ${payload.userId}`);

    // At this point, the token's signature and expiry are already verified by passport-jwt.
    // You can add additional checks, like ensuring the user still exists in the database
    // or hasn't been deactivated.
    const user = await this.usersService.findById(payload.userId);
    if (!user) {
      this.logger.warn(`User from JWT payload not found in database: ${payload.userId}`);
      throw new UnauthorizedException('User not found or token refers to a non-existent user.');
    }

    // You can choose what to return. This object will be attached to `request.user`.
    // It's good practice to return a payload that includes up-to-date information if needed,
    // or at least the essential identifiers.
    return {
      userId: user.id, // Use ID from DB for consistency and to ensure user exists
      email: user.email, // Use email from DB for consistency
      verificationStatus: user.verificationStatus, // Get the LATEST verification status from DB
      roles: payload.roles, // Pass through roles from original JWT payload if they exist
      // Do not include sensitive information like passwordHash here.
    };
  }
}
