// File: ./your-dating-app-backend/apps/auth-service/src/auth/strategies/jwt.strategy.ts
// Purpose: Passport strategy for validating JWTs.
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { UsersService } from '../users/users.service';
import { JWT_ACCESS_SECRET_KEY } from '../constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') { // Naming the strategy 'jwt'
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Standard extraction from 'Bearer <token>' header
      ignoreExpiration: false, // Passport-jwt will automatically handle expired tokens
      secretOrKey: configService.get<string>(JWT_ACCESS_SECRET_KEY),
    });
    this.logger.log('JwtStrategy initialized.');
  }

  /**
   * This method is called by Passport after it has successfully verified the JWT's signature
   * and that it has not expired. The 'payload' argument is the decoded JSON object from the JWT.
   * The value returned from this method will be attached to the request object (e.g., req.user for HTTP).
   */
  async validate(payload: JwtPayload): Promise<JwtPayload> {
    this.logger.debug(`Validating JWT payload for userId: ${payload.userId}`);
    const user = await this.usersService.findById(payload.userId);
    if (!user) {
      this.logger.warn(`User from JWT payload not found in database: ${payload.userId}`);
      throw new UnauthorizedException('User not found or token refers to a non-existent user.');
    }

    // Return a new object that will be attached to the request context.
    // It's good practice to return up-to-date info from the DB.
    return {
      userId: user.id,
      email: user.email,
      verificationStatus: user.verificationStatus, // Get the LATEST verification status from DB
      roles: payload.roles, // Pass through roles from original JWT payload if they exist
    };
  }
}