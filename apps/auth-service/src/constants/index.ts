export const JWT_ACCESS_SECRET_KEY = 'JWT_ACCESS_SECRET';
export const JWT_ACCESS_EXPIRATION_KEY = 'JWT_ACCESS_EXPIRES_IN';
export const JWT_REFRESH_SECRET_KEY = 'JWT_REFRESH_SECRET';
export const JWT_REFRESH_EXPIRES_IN_KEY = 'JWT_REFRESH_EXPIRES_IN';
export const BCRYPT_SALT_ROUNDS_KEY = 'BCRYPT_SALT_ROUNDS';

// RabbitMQ Related
export const RABBITMQ_URI_KEY = 'RABBITMQ_URI';
export const RABBITMQ_AUTH_QUEUE_KEY = 'RABBITMQ_AUTH_QUEUE';
export const AUTH_SERVICE_RABBITMQ_CLIENT = 'AUTH_RMQ_CLIENT'; // Injection token

// Event Names (for RabbitMQ routing keys/patterns)
export const USER_REGISTERED_EVENT = 'user.registered';
export const USER_VERIFICATION_STATUS_UPDATED_EVENT = 'user.verification.status.updated';