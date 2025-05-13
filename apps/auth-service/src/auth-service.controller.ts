import { Controller, Inject } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { Metadata, ServerUnaryCall } from '@grpc/grpc-js';
import { AuthServiceService } from './auth-service.service'; // Assuming this service holds logic
import {
  AUTH_SERVICE_NAME,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  VerificationStatusResponse,
  UserIdRequest,
} from '@app/proto-definitions/auth'; // Assuming you export constants/types from the lib

@Controller()
export class AuthServiceController {
  constructor(
    @Inject(AuthServiceService) // Inject the service
    private readonly authService: AuthServiceService,
  ) {}

  // Maps to the 'Register' RPC method in auth.proto
  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  register(
    data: RegisterRequest,
    metadata?: Metadata, // Optional metadata
    call?: ServerUnaryCall<any, any>, // Optional call context
  ): Promise<RegisterResponse> {
    // Use Promise for async operations
    console.log(`Received Register request for email: ${data.email}`);
    return this.authService.registerUser(data); // Delegate to service
  }

  // Maps to the 'Login' RPC method
  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  login(data: LoginRequest): Promise<LoginResponse> {
    console.log(`Received Login request for email: ${data.email}`);
    return this.authService.loginUser(data); // Delegate to service
  }

  // Maps to 'CheckVerificationStatus'
  @GrpcMethod(AUTH_SERVICE_NAME, 'CheckVerificationStatus')
  checkVerificationStatus(
    data: UserIdRequest,
  ): Promise<VerificationStatusResponse> {
    console.log(
      `Received CheckVerificationStatus request for user: ${data.userId}`,
    );
    return this.authService.getVerificationStatus(data.userId); // Delegate
  }
}
