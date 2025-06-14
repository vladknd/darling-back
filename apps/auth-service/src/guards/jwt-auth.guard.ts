// File: ./your-dating-app-backend/apps/auth-service/src/auth/guards/jwt-auth.guard.ts
// Purpose: A guard to protect routes/gRPC methods that require JWT authentication.
import { Injectable, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RpcException } from '@nestjs/microservices';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  /**
   * This method is called by NestJS before the route handler.
   * For a pure gRPC service like AuthService, direct use of this guard on a gRPC method
   * is less common, as the API Gateway is expected to perform the initial JWT validation.
   * However, this guard is still valuable if you need service-to-service authentication
   * where one service calls another and passes along the user's JWT in the gRPC metadata.
   */
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    this.logger.debug('JwtAuthGuard canActivate called. Will invoke Passport strategy.');
    return super.canActivate(context);
  }

  /**
   * This method is called by Passport after the strategy's validate() method.
   * It allows customizing how an error or user object is handled.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      const errorMessage = info?.message || 'Unauthorized access';
      this.logger.warn(`JWT authentication failed: ${errorMessage}`, info?.stack || err);
      if (context.getType() === 'rpc') {
        // For gRPC, throw an RpcException with a standard gRPC status code.
        // 16 corresponds to UNAUTHENTICATED.
        throw new RpcException({ code: 16, message: errorMessage });
      } else {
        // For HTTP (if this guard was ever used in an HTTP context)
        throw err || new UnauthorizedException(errorMessage);
      }
    }
    this.logger.debug(`JWT authentication successful for user: ${user.userId}`);
    return user; // This attaches the user object (from JwtStrategy.validate) to the request context
  }
}
