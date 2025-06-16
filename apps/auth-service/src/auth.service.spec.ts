// File: ./your-dating-app-backend/apps/auth-service/src/auth-service.service.spec.ts
// Purpose: Corrected unit tests for the AuthServiceService.

import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth-service.service';
import { UsersService } from './users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserCredential, VerificationStatus } from './users/entities/user-credential.entity';
import * as bcrypt from 'bcrypt';
import { of } from 'rxjs';

// Import the actual constant keys to ensure consistency
import {
  AUTH_SERVICE_RABBITMQ_CLIENT,
  BCRYPT_SALT_ROUNDS_KEY,
  JWT_REFRESH_EXPIRES_IN_KEY,
  JWT_REFRESH_SECRET_KEY,
  USER_REGISTERED_EVENT,
} from './constants';

jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('hashedPassword'),
  compare: jest.fn(),
}));

// Mocks for dependencies
const mockUsersService = {
  findByEmail: jest.fn(),
  createUser: jest.fn(),
  storeRefreshToken: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn(),
};

// --- FIX ---
// The mockConfigService now uses the imported constants for the keys.
// This ensures it matches what the real service uses.
const mockConfigService = {
  get: jest.fn((key: string) => {
    if (key === BCRYPT_SALT_ROUNDS_KEY) return 10;
    if (key === JWT_REFRESH_SECRET_KEY) return 'test-refresh-secret'; // This key now matches the constant
    if (key === JWT_REFRESH_EXPIRES_IN_KEY) return '7d';
    return null;
  }),
};

const mockRabbitMqClient = {
  emit: jest.fn().mockReturnValue(of({})), // Return a completing observable for emit
};

describe('AuthServiceService', () => {
  let service: AuthService;
  let usersService: UsersService;
  let jwtService: JwtService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: mockUsersService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: AUTH_SERVICE_RABBITMQ_CLIENT, useValue: mockRabbitMqClient },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get<UsersService>(UsersService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    const registerDto = { email: 'new@example.com', password: 'password123' };

    it('should successfully register a new user', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);
      const newUser: UserCredential = {
        id: 'new-uuid',
        email: registerDto.email,
        passwordHash: 'hashedPassword',
        verificationStatus: VerificationStatus.UNVERIFIED,
        refreshTokens: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockUsersService.createUser.mockResolvedValue(newUser);

      const result = await service.register(registerDto);

      expect(bcrypt.hash).toHaveBeenCalledWith(registerDto.password, 10);
      expect(usersService.createUser).toHaveBeenCalledWith(registerDto, 'hashedPassword');
      expect(mockRabbitMqClient.emit).toHaveBeenCalledWith(USER_REGISTERED_EVENT, expect.any(Object));
      expect(result).toEqual({
        userId: newUser.id,
        message: 'Registration successful. Please complete identity verification.',
      });
    });
  });

  describe('login', () => {
    const loginDto = { email: 'test@example.com', password: 'password123' };
    const mockUser: UserCredential = {
      id: 'uuid-123',
      email: 'test@example.com',
      passwordHash: 'hashedPassword',
      verificationStatus: VerificationStatus.VERIFIED,
      refreshTokens: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('should successfully log in and return tokens', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      
      // --- FIX ---
      // The mock implementation for jwt.sign is now more robust.
      // It correctly differentiates between calls for access and refresh tokens.
      mockJwtService.sign.mockImplementation((payload, options) => {
        if (options?.secret === 'test-refresh-secret') {
          return 'mock-refresh-token';
        }
        return 'mock-access-token';
      });

      const result = await service.login(loginDto);

      expect(usersService.findByEmail).toHaveBeenCalledWith(loginDto.email);
      expect(bcrypt.compare).toHaveBeenCalledWith(loginDto.password, mockUser.passwordHash);
      expect(jwtService.sign).toHaveBeenCalledTimes(2);
      expect(usersService.storeRefreshToken).toHaveBeenCalled();
      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token'); // This assertion will now pass
    });
  });
});
