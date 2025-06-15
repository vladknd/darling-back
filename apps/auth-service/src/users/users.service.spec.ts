// File: ./your-dating-app-backend/apps/auth-service/src/users/users.service.spec.ts
// Purpose: Unit tests for the UsersService.

import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { UserCredentialRepository } from './repositories/user-credential.repository';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { NotFoundException } from '@nestjs/common';
import { UserCredential, VerificationStatus } from './entities/user-credential.entity';
import { RefreshToken } from './entities/refresh-token.entity';

// --- Mock Repositories ---
// We create mock versions of our custom repositories.
// The `jest.fn()` creates mock functions for each method.
const mockUserCredentialRepository = {
  createUser: jest.fn(),
  findByEmail: jest.fn(),
  findById: jest.fn(),
  updateUserVerificationStatus: jest.fn(),
};

const mockRefreshTokenRepository = {
  createAndSave: jest.fn(),
  findByToken: jest.fn(),
  revoke: jest.fn(),
};

describe('UsersService', () => {
  let service: UsersService;
  let userCredentialRepository: UserCredentialRepository;

  beforeEach(async () => {
    // Reset mocks before each test to ensure a clean state
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: UserCredentialRepository,
          useValue: mockUserCredentialRepository, // Provide the mock instead of the real repository
        },
        {
          provide: RefreshTokenRepository,
          useValue: mockRefreshTokenRepository, // Provide the mock
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    userCredentialRepository = module.get<UserCredentialRepository>(UserCredentialRepository);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createUser', () => {
    it('should call userCredentialRepository.createUser with correct data', async () => {
      const registerDto = { email: 'test@example.com', password: 'password123' };
      const hashedPassword = 'hashedPassword';
      
      // FIX: Create a complete mock UserCredential object
      const mockUser: UserCredential = {
        id: 'uuid-123',
        email: registerDto.email,
        passwordHash: hashedPassword,
        verificationStatus: VerificationStatus.UNVERIFIED,
        refreshTokens: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // When the repository's createUser method is called, make it return our mockUser
      mockUserCredentialRepository.createUser.mockResolvedValue(mockUser);

      const result = await service.createUser(registerDto, hashedPassword);

      // Assert that the repository method was called correctly
      expect(userCredentialRepository.createUser).toHaveBeenCalledWith(registerDto, hashedPassword);
      // Assert that the service returned the expected result
      expect(result).toEqual(mockUser);
    });
  });

  describe('findById', () => {
    it('should call userCredentialRepository.findById and return a user', async () => {
        const userId = 'uuid-123';
        const mockUser: UserCredential = {
            id: userId,
            email: 'test@example.com',
            passwordHash: 'hashedPassword',
            verificationStatus: VerificationStatus.VERIFIED,
            refreshTokens: [],
            createdAt: new Date(),
            updatedAt: new Date(),
        };
        mockUserCredentialRepository.findById.mockResolvedValue(mockUser);

        const result = await service.findById(userId);

        expect(userCredentialRepository.findById).toHaveBeenCalledWith(userId);
        expect(result).toEqual(mockUser);
    });

    it('should return null if user is not found', async () => {
        const userId = 'non-existent-uuid';
        mockUserCredentialRepository.findById.mockResolvedValue(null);

        const result = await service.findById(userId);

        expect(userCredentialRepository.findById).toHaveBeenCalledWith(userId);
        expect(result).toBeNull();
    });
  });

  describe('updateUserVerificationStatus', () => {
    it('should find a user and call the repository to update their status', async () => {
      const userId = 'uuid-123';
      const newStatus = VerificationStatus.VERIFIED;
      
      const existingUser: UserCredential = {
        id: userId,
        email: 'test@example.com',
        passwordHash: 'hashedPassword',
        verificationStatus: VerificationStatus.UNVERIFIED,
        refreshTokens: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      
      // Mock both the find and update methods
      mockUserCredentialRepository.findById.mockResolvedValue(existingUser);
      mockUserCredentialRepository.updateUserVerificationStatus.mockResolvedValue({ ...existingUser, verificationStatus: newStatus });

      await service.updateUserVerificationStatus(userId, newStatus);

      expect(userCredentialRepository.findById).toHaveBeenCalledWith(userId);
      expect(userCredentialRepository.updateUserVerificationStatus).toHaveBeenCalledWith(existingUser, newStatus);
    });

    it('should throw NotFoundException if user does not exist', async () => {
      const userId = 'non-existent-uuid';
      mockUserCredentialRepository.findById.mockResolvedValue(null);

      // The service method should throw an exception if the user isn't found before an update
      await expect(service.updateUserVerificationStatus(userId, VerificationStatus.VERIFIED)).rejects.toThrow(NotFoundException);
    });
  });

  describe('findActiveRefreshToken', () => {
    it('should find an active token and return it', async () => {
        const tokenString = 'valid-refresh-token';
        // FIX: Create a complete mock RefreshToken object
        const mockToken: RefreshToken = { 
            id: 'token-uuid-1',
            userCredentialId: 'user-uuid-1',
            userCredential: new UserCredential(), // Add a placeholder or full mock user if needed
            token: tokenString, 
            expiresAt: new Date(Date.now() + 10000),
            isRevoked: false,
            createdAt: new Date(),
            replacedByToken: null
        };
        mockRefreshTokenRepository.findByToken.mockResolvedValue(mockToken);

        const result = await service.findActiveRefreshToken(tokenString);

        expect(mockRefreshTokenRepository.findByToken).toHaveBeenCalledWith(tokenString);
        expect(result).toEqual(mockToken);
    });

    it('should return null and revoke an expired token', async () => {
        const tokenString = 'expired-refresh-token';
        const mockToken: RefreshToken = { 
            id: 'token-uuid-2',
            userCredentialId: 'user-uuid-2',
            userCredential: new UserCredential(),
            token: tokenString, 
            expiresAt: new Date(Date.now() - 10000), // Expired in the past
            isRevoked: false,
            createdAt: new Date(),
            replacedByToken: null
        };
        mockRefreshTokenRepository.findByToken.mockResolvedValue(mockToken);
        mockRefreshTokenRepository.revoke.mockResolvedValue({ ...mockToken, isRevoked: true });

        const result = await service.findActiveRefreshToken(tokenString);

        expect(mockRefreshTokenRepository.findByToken).toHaveBeenCalledWith(tokenString);
        expect(mockRefreshTokenRepository.revoke).toHaveBeenCalledWith(mockToken);
        expect(result).toBeNull();
    });
  });
});
