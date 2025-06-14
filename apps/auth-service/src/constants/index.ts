// File: ./your-dating-app-backend/apps/auth-service/src/auth/constants/index.ts
// Purpose: Stores constants related to authentication, configuration keys, and event names.

// --- Environment Variable Keys (used with ConfigService) ---

// JWT Access Token Configuration
export const JWT_ACCESS_SECRET_KEY = 'JWT_ACCESS_SECRET';
export const JWT_ACCESS_EXPIRATION_KEY = 'JWT_ACCESS_EXPIRES_IN';

// JWT Refresh Token Configuration
export const JWT_REFRESH_SECRET_KEY = 'JWT_REFRESH_SECRET';
export const JWT_REFRESH_EXPIRES_IN_KEY = 'JWT_REFRESH_EXPIRES_IN';

// Bcrypt Configuration
export const BCRYPT_SALT_ROUNDS_KEY = 'BCRYPT_SALT_ROUNDS';

// RabbitMQ Related Configuration
export const RABBITMQ_URI_KEY = 'RABBITMQ_URI';
export const RABBITMQ_AUTH_QUEUE_KEY = 'RABBITMQ_AUTH_QUEUE'; // Default queue for this service's client

// --- NestJS Dependency Injection Tokens ---
export const AUTH_SERVICE_RABBITMQ_CLIENT = 'AUTH_RMQ_CLIENT'; // DI Token for RabbitMQ ClientProxy

// --- Event Names / Routing Keys (for RabbitMQ) ---
export const USER_REGISTERED_EVENT = 'user.registered'; // Pattern for user registration event
export const USER_VERIFICATION_STATUS_UPDATED_EVENT = 'user.verification.status.updated'; // Pattern for IDV status changes
