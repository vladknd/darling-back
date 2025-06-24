// File: apps/auth-service/src/auth-service.controller.spec.ts
// Purpose: Unit tests for the AuthServiceController.

import { Test, TestingModule } from '@nestjs/testing';
import { RpcException } from '@nestjs/microservices';
import { AuthServiceController } from './auth-service.controller';
import { AuthService } from './auth-service.service';
import {
  RegisterRequest,
  LoginRequest,
  RefreshAccessTokenRequest,
  ValidateAccessTokenRequest,
  UserIdRequest,
  ProcessIdvWebhookRequest,
} from '@app/proto-definitions/auth';

// Create a mock AuthService with all the methods we need to test.
// jest.fn() creates a mock function that we can spy on.
const mockAuthService = {
  register: jest.fn(),
  login: jest.fn(),
  refreshAccessToken: jest.fn(),
  validateAccessToken: jest.fn(),
  getVerificationStatus: jest.fn(),
  processIdvWebhook: jest.fn(),
};

describe('AuthServiceController', () => {
  let controller: AuthServiceController;
  let service: AuthService;

  beforeEach(async () => {
    // Reset mocks before each test to ensure a clean slate
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthServiceController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService, // Use our mock service instead of the real one
        },
      ],
    }).compile();

    controller = module.get<AuthServiceController>(AuthServiceController);
    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should call authService.registerUser with the correct payload', async () => {
      const payload: RegisterRequest = { email: 'test@example.com', password: 'password' };
      const expectedResult = { userId: '123', message: 'Success' };
      mockAuthService.register.mockResolvedValue(expectedResult);

      const result = await controller.register(payload);

      expect(service.register).toHaveBeenCalledWith(payload);
      expect(result).toEqual(expectedResult);
    });

    it('should throw RpcException if email is missing', async () => {
      const payload = { password: 'password' } as RegisterRequest;
      await expect(controller.register(payload)).rejects.toThrow(
        new RpcException('Email and password are required for registration.'),
      );
    });
  });

  describe('login', () => {
    it('should call authService.loginUser with the correct payload', async () => {
      const payload: LoginRequest = { email: 'test@example.com', password: 'password' };
      const expectedResult = { accessToken: 'abc', refreshToken: 'def', userId: '123', verificationStatus: 'VERIFIED' };
      mockAuthService.login.mockResolvedValue(expectedResult);

      const result = await controller.login(payload);

      expect(service.login).toHaveBeenCalledWith(payload);
      expect(result).toEqual(expectedResult);
    });

    it('should throw RpcException if password is missing', async () => {
        const payload = { email: 'test@example.com' } as LoginRequest;
        await expect(controller.login(payload)).rejects.toThrow(
            new RpcException('Email and password are required for login.'),
        );
    });
  });

  describe('refreshAccessToken', () => {
    it('should call authService.refreshAccessToken with the correct payload', async () => {
        const payload: RefreshAccessTokenRequest = { refreshToken: 'test-token' };
        mockAuthService.refreshAccessToken.mockResolvedValue({ accessToken: 'new-abc', refreshToken: 'new-def', userId: '123', verificationStatus: 'VERIFIED' });
        
        await controller.refreshAccessToken(payload);
        
        expect(service.refreshAccessToken).toHaveBeenCalledWith(payload);
    });

    it('should throw RpcException if refreshToken is missing', async () => {
        const payload = {} as RefreshAccessTokenRequest;
        await expect(controller.refreshAccessToken(payload)).rejects.toThrow(
            new RpcException('Refresh token is required.'),
        );
    });
  });

  describe('validateAccessToken', () => {
    it('should call authService.validateAccessToken with the correct payload', async () => {
        const payload: ValidateAccessTokenRequest = { accessToken: 'test-token' };
        mockAuthService.validateAccessToken.mockResolvedValue({ isValid: true, userId: '123' });

        await controller.validateAccessToken(payload);
        
        expect(service.validateAccessToken).toHaveBeenCalledWith(payload);
    });

    it('should throw RpcException if accessToken is missing', async () => {
        const payload = {} as ValidateAccessTokenRequest;
        await expect(controller.validateAccessToken(payload)).rejects.toThrow(
            new RpcException('Access token is required for validation.'),
        );
    });
  });

  describe('getVerificationStatus', () => {
    it('should call authService.getVerificationStatus with the correct payload', async () => {
        const payload: UserIdRequest = { userId: 'user-123' };
        mockAuthService.getVerificationStatus.mockResolvedValue({ userId: 'user-123', status: 'UNVERIFIED' });

        await controller.getVerificationStatus(payload);

        expect(service.getVerificationStatus).toHaveBeenCalledWith(payload);
    });

    it('should throw RpcException if userId is missing', async () => {
        const payload = {} as UserIdRequest;
        await expect(controller.getVerificationStatus(payload)).rejects.toThrow(
            new RpcException('User ID is required.'),
        );
    });
  });

  describe('processIdvWebhook', () => {
    it('should call authService.processIdvWebhook with the correct payload', async () => {
        const payload: ProcessIdvWebhookRequest = { userId: 'user-123', newStatus: 'VERIFIED', idvProviderReference: 'ref-abc', details: 'details...' };
        mockAuthService.processIdvWebhook.mockResolvedValue({ success: true, message: 'Updated' });

        await controller.processIdvWebhook(payload);

        expect(service.processIdvWebhook).toHaveBeenCalledWith(payload);
    });

    it('should throw RpcException if newStatus is missing', async () => {
        const payload = { userId: 'user-123' } as ProcessIdvWebhookRequest;
        await expect(controller.processIdvWebhook(payload)).rejects.toThrow(
            new RpcException('User ID and new status are required for IDV webhook processing.'),
        );
    });
  });
});