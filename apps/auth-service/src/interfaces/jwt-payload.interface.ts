// File: ./your-dating-app-backend/apps/auth-service/src/auth/interfaces/jwt-payload.interface.ts
// Purpose: Defines the structure of the JWT payload.
import { VerificationStatus } from '../users/entities/user-credential.entity';

export interface JwtPayload {
  /**
   * User ID (subject of the token)
   */
  userId: string;

  /**
   * User's email
   */
  email: string;

  /**
   * Current verification status of the user at the time of token issuance
   */
  verificationStatus: VerificationStatus;

  /**
   * Optional: Roles assigned to the user
   */
  roles?: string[];

  /**
   * Standard JWT claim: Issued At (seconds since epoch) - Populated by jwt.sign()
   */
  iat?: number;

  /**
   * Standard JWT claim: Expiration Time (seconds since epoch) - Populated by jwt.sign()
   */
  exp?: number;
}
