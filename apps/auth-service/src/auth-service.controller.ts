import { Controller, Logger, UsePipes, ValidationPipe } from '@nestjs/common';
import { GrpcMethod, Payload, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth-service.service';
import {
  AUTH_SERVICE_NAME,
  RegisterRequest, RegisterResponse,
  LoginRequest, LoginResponse,
  UserIdRequest, VerificationStatusResponse,
} from '@app/proto-definitions/auth';

@Controller()
export class AuthServiceController {
  private readonly logger = new Logger(AuthServiceController.name);

  constructor(private readonly authService: AuthService) {}

  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  // If RegisterRequest was a class DTO with class-validator decorators:
  // @UsePipes(new ValidationPipe({ transform: true, whitelist: true, exceptionFactory: (errors) => new RpcException(errors) }))
  async register(@Payload() data: RegisterRequest): Promise<RegisterResponse> {
    this.logger.log(`gRPC Register called with email: ${data.email?.substring(0,3)}...`);
    // Basic validation for gRPC payloads can be done here or in the service
    if (!data.email || !data.password) {
        throw new RpcException('Email and password are required for registration.');
    }
    return this.authService.registerUser(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  async login(@Payload() data: LoginRequest): Promise<LoginResponse> {
    this.logger.log(`gRPC Login called for email: ${data.email?.substring(0,3)}...`);
    if (!data.email || !data.password) {
        throw new RpcException('Email and password are required for login.');
    }
    return this.authService.loginUser(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'RefreshAccessToken')
  async refreshAccessToken(@Payload() data: RefreshAccessTokenRequest): Promise<LoginResponse> {
    this.logger.log(`gRPC RefreshAccessToken called.`);
    if (!data.refreshToken) {
        throw new RpcException('Refresh token is required.');
    }
    return this.authService.refreshAccessToken(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'ValidateAccessToken')
  async validateAccessToken(@Payload() data: ValidateAccessTokenRequest): Promise<ValidateAccessTokenResponse> {
    this.logger.log(`gRPC ValidateAccessToken called.`);
    if (!data.accessToken) {
        throw new RpcException('Access token is required for validation.');
    }
    return this.authService.validateAccessToken(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'GetVerificationStatus')
  async getVerificationStatus(@Payload() data: UserIdRequest): Promise<VerificationStatusResponse> {
    this.logger.log(`gRPC GetVerificationStatus called for userId: ${data.userId}`);
    if (!data.userId) {
        throw new RpcException('User ID is required.');
    }
    return this.authService.getVerificationStatus(data);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'ProcessIdvWebhook')
  async processIdvWebhook(@Payload() data: ProcessIdvWebhookRequest): Promise<ProcessIdvWebhookResponse> {
    this.logger.log(`gRPC ProcessIdvWebhook called for userId: ${data.userId} with status ${data.newStatus}`);
    if (!data.userId || !data.newStatus) {
        throw new RpcException('User ID and new status are required for IDV webhook processing.');
    }
    return this.authService.processIdvWebhook(data);
  }
}