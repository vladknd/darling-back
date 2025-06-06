// File: ./your-dating-app-backend/apps/auth-service/src/auth/guards/jwt-auth.guard.ts
// Purpose: A guard to protect routes/gRPC methods that require JWT authentication.
import { Injectable, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RpcException } from '@nestjs/microservices';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') { // Specifies that this guard uses the 'jwt' strategy
  private readonly logger = new Logger(JwtAuthGuard.name);

  /**
   * This method is called by NestJS before the route handler.
   * For gRPC, the ExecutionContext needs to be adapted to extract user/token.
   * If the API Gateway validates the JWT and passes user info in gRPC metadata,
   * this guard in AuthService might be more about checking for that trusted metadata
   * rather than re-validating a JWT string from metadata.
   *
   * However, if AuthService exposes gRPC methods that are called by other internal services
   * which pass along a JWT in metadata, then this guard (with proper metadata extraction in JwtStrategy)
   * would be appropriate.
   */
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    // For gRPC, the 'request' object is different.
    // If you intend to use this guard for gRPC methods and expect a JWT in metadata:
    // 1. Your JwtStrategy's `jwtFromRequest` needs to be configured to extract from gRPC metadata.
    //    Example for JwtStrategy constructor:
    //    jwtFromRequest: ExtractJwt.fromExtractors([(rpcContext: any) => {
    //      try {
    //        const metadata = rpcContext.getContext?.() as grpc.Metadata; // For @grpc/grpc-js
    //        if (metadata) {
    //          const authHeader = metadata.get('authorization');
    //          if (authHeader && authHeader.length > 0) {
    //            const token = authHeader[0].toString().replace('Bearer ', '');
    //            return token;
    //          }
    //        }
    //      } catch (e) { this.logger.error('Error extracting token from gRPC metadata', e); }
    //      return null;
    //    }]),
    //
    // 2. The `getRequest` method can be overridden here if needed to shape what Passport sees.
    //    However, with a custom extractor in the strategy, this might not be necessary.

    this.logger.debug('JwtAuthGuard canActivate called.');
    return super.canActivate(context); // Calls the Passport strategy
  }

  /**
   * This method is called by Passport after the strategy's validate() method.
   * It allows you to customize how an error or user object is handled.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext, status?: any): any {
    if (err || !user) {
      const errorMessage = info?.message || 'Unauthorized access';
      this.logger.warn(`JWT authentication failed: ${errorMessage}`, err || info);
      if (context.getType() === 'rpc') {
        // For gRPC, throw an RpcException.
        // The gRPC status code can be mapped from HTTP status codes or set explicitly.
        // e.g., UNAUTHENTICATED (16)
        throw new RpcException({ code: 16, message: errorMessage });
      } else {
        // For HTTP (if this guard was used in an HTTP context)
        throw err || new UnauthorizedException(errorMessage);
      }
    }
    this.logger.debug(`JWT authentication successful for user: ${user.userId}`);
    return user; // This attaches the user object (from JwtStrategy.validate) to the request context
  }
}
