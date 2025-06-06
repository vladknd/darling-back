// File: ./your-dating-app-backend/apps/auth-service/src/auth-service.module.ts
// Purpose: Root module for the auth-service.
import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ClientsModule, Transport } from '@nestjs/microservices';
import * as Joi from 'joi';

import { AuthServiceController } from './auth-service.controller';
import { AuthService } from './auth-service.service';
import { UsersModule } from './users/usesrs.module';
import { UserCredential } from './users/entities/user-credential.entity';
import { RefreshToken } from './users/entities/refresh-token.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import {
  JWT_ACCESS_SECRET_KEY, JWT_ACCESS_EXPIRATION_KEY, JWT_REFRESH_SECRET_KEY,
  JWT_REFRESH_EXPIRES_IN_KEY, RABBITMQ_URI_KEY, RABBITMQ_AUTH_QUEUE_KEY,
  AUTH_SERVICE_RABBITMQ_CLIENT, BCRYPT_SALT_ROUNDS_KEY
} from './constants'; // Ensure this path is correct

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes ConfigService available throughout this AuthService app
      envFilePath: process.env.NODE_ENV === 'test' ? '.env.test' : '.env', // Load .env file from project root
      ignoreEnvFile: process.env.NODE_ENV === 'production', // In prod, rely on actual environment variables
      validationSchema: Joi.object({ // Environment variable validation
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
        AUTH_SERVICE_PORT: Joi.number().default(50051),
        AUTH_DB_HOST: Joi.string().required(),
        AUTH_DB_PORT: Joi.number().default(5432),
        AUTH_DB_USERNAME: Joi.string().required(),
        AUTH_DB_PASSWORD: Joi.string().required(),
        AUTH_DB_DATABASE: Joi.string().required(),
        JWT_ACCESS_SECRET: Joi.string().min(32).required(), // Enforce minimum length for secrets
        JWT_ACCESS_EXPIRES_IN: Joi.string().default('15m'),
        JWT_REFRESH_SECRET: Joi.string().min(32).required(),
        JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),
        RABBITMQ_URI: Joi.string().uri({ scheme: ['amqp', 'amqps'] }).required(),
        RABBITMQ_AUTH_QUEUE: Joi.string().default('auth_events_queue'),
        BCRYPT_SALT_ROUNDS: Joi.number().integer().min(8).max(14).default(10),
      }),
      validationOptions: {
        allowUnknown: true, // Allow other env vars not defined in the schema
        abortEarly: false,  // Show all validation errors at once
      },
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }), // Default strategy for AuthGuard('jwt')
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>(JWT_ACCESS_SECRET_KEY),
        signOptions: { expiresIn: configService.get<string>(JWT_ACCESS_EXPIRATION_KEY) },
      }),
      inject: [ConfigService],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('AUTH_DB_HOST'),
        port: configService.get<number>('AUTH_DB_PORT'),
        username: configService.get<string>('AUTH_DB_USERNAME'),
        password: configService.get<string>('AUTH_DB_PASSWORD'),
        database: configService.get<string>('AUTH_DB_DATABASE'),
        entities: [UserCredential, RefreshToken],
        // In development, synchronize can be true. For production, use migrations.
        synchronize: configService.get<string>('NODE_ENV') !== 'production',
        logging: configService.get<string>('NODE_ENV') !== 'production' ? 'all' : ['error', 'warn'],
        // autoLoadEntities: true, // Alternative to explicitly listing entities if they follow a pattern
      }),
      inject: [ConfigService],
    }),
    UsersModule, // Manages UserCredential & RefreshToken repositories and services
    ClientsModule.registerAsync([ // Setup for RabbitMQ client
      {
        name: AUTH_SERVICE_RABBITMQ_CLIENT, // Injection token for the RabbitMQ client
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.RMQ,
          options: {
            urls: [configService.get<string>(RABBITMQ_URI_KEY)],
            queue: configService.get<string>(RABBITMQ_AUTH_QUEUE_KEY), // Default queue for this client
            queueOptions: {
              durable: true, // Queue will survive broker restarts
            },
            noAck: false, // Explicitly set to false for reliability; messages must be ack'd. Default for emit is true.
            persistent: true, // Make messages persistent by default for this client's publications
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [AuthServiceController], // Handles gRPC requests
  providers: [AuthService, JwtStrategy, Logger], // Logger can be injected generally
})
export class AuthServiceModule {}
