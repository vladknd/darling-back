// File: ./your-dating-app-backend/apps/auth-service/src/auth-service.service.spec.ts
// Purpose: Unit tests for the AuthServiceService.

import { Test, TestingModule } from '@nestjs/testing';
import { AuthService} from './auth-service.service';
import { UsersService } from './users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { UserCredential, VerificationStatus } from './users/entities/user-credential.entity';
import * as bcrypt from 'bcrypt';
import { AUTH_SERVICE_RABBITMQ_CLIENT, USER_REGISTERED_EVENT } from './constants';

jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('hashedPassword'),
  compare: jest.fn(),
}));

const mockUsersService = {
  findByEmail: jest.fn(),
  createUser: jest.fn(),
  storeRefreshToken: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn().mockReturnValue('mocked-jwt-token'),
};

const mockConfigService = {
  get: jest.fn((key: string) => {
    if (key === 'BCRYPT_SALT_ROUNDS') return 10;
    if (key === 'JWT_REFRESH_SECRET_KEY') return 'test-refresh-secret';
    if (key === 'JWT_REFRESH_EXPIRES_IN_KEY') return '7d';
    return null;
  }),
};

const mockRabbitMqClient = {
  emit: jest.fn(),
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

      const result = await service.registerUser(registerDto);

      expect(bcrypt.hash).toHaveBeenCalledWith(registerDto.password, 10);
      expect(usersService.createUser).toHaveBeenCalledWith(registerDto, 'hashedPassword');
      expect(mockRabbitMqClient.emit).toHaveBeenCalledWith(USER_REGISTERED_EVENT, expect.any(Object));
      expect(result).toEqual({
        userId: newUser.id,
        message: 'Registration successful. Please complete identity verification.',
      });
    });

    it('should throw an RpcException if email already exists', async () => {
      mockUsersService.findByEmail.mockResolvedValue({} as UserCredential);
      await expect(service.registerUser(registerDto)).rejects.toThrow(
        new RpcException('User with this email already exists.')
      );
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
      mockJwtService.sign.mockImplementation((payload, options) => {
        return options?.secret === 'test-refresh-secret' ? 'mock-refresh-token' : 'mock-access-token';
      });

      const result = await service.loginUser(loginDto);

      expect(usersService.findByEmail).toHaveBeenCalledWith(loginDto.email);
      expect(bcrypt.compare).toHaveBeenCalledWith(loginDto.password, mockUser.passwordHash);
      expect(jwtService.sign).toHaveBeenCalledTimes(2);
      expect(usersService.storeRefreshToken).toHaveBeenCalled();
      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token');
    });
  });
});
