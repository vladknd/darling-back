// File: ./your-dating-app-backend/apps/auth-service/src/auth-service.module.ts
// Purpose: Root module for the auth-service, tying everything together.
import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ClientsModule, Transport } from '@nestjs/microservices';
import * as Joi from 'joi';

import { AuthServiceController } from './auth-service.controller';
import { AuthServiceService } from './auth-service.service';
import { UsersModule } from './users/users.module';
import { UserCredential } from './users/entities/user-credential.entity';
import { RefreshToken } from './users/entities/refresh-token.entity';
import { JwtStrategy } from './auth/strategies/jwt.strategy';
import {
  JWT_ACCESS_SECRET_KEY, JWT_ACCESS_EXPIRATION_KEY, JWT_REFRESH_SECRET_KEY,
  JWT_REFRESH_EXPIRES_IN_KEY, RABBITMQ_URI_KEY, RABBITMQ_AUTH_QUEUE_KEY,
  AUTH_SERVICE_RABBITMQ_CLIENT, BCRYPT_SALT_ROUNDS_KEY
} from './auth/constants';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: process.env.NODE_ENV === 'test' ? '.env.test' : '.env',
      ignoreEnvFile: process.env.NODE_ENV === 'production',
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
        AUTH_SERVICE_PORT: Joi.number().default(50051),
        AUTH_DB_HOST: Joi.string().required(),
        AUTH_DB_PORT: Joi.number().default(5432),
        AUTH_DB_USERNAME: Joi.string().required(),
        AUTH_DB_PASSWORD: Joi.string().required(),
        AUTH_DB_DATABASE: Joi.string().required(),
        JWT_ACCESS_SECRET: Joi.string().min(32).required(),
        JWT_ACCESS_EXPIRES_IN: Joi.string().default('15m'),
        JWT_REFRESH_SECRET: Joi.string().min(32).required(),
        JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),
        RABBITMQ_URI: Joi.string().uri({ scheme: ['amqp', 'amqps'] }).required(),
        RABBITMQ_AUTH_QUEUE: Joi.string().default('auth_events_queue'),
        BCRYPT_SALT_ROUNDS: Joi.number().integer().min(8).max(14).default(10),
      }),
      validationOptions: {
        allowUnknown: true,
        abortEarly: false,
      },
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
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
        synchronize: configService.get<string>('NODE_ENV') !== 'production',
        logging: configService.get<string>('NODE_ENV') !== 'production' ? 'all' : ['error', 'warn'],
      }),
      inject: [ConfigService],
    }),
    UsersModule, // Manages all user data access logic
    ClientsModule.registerAsync([
      {
        name: AUTH_SERVICE_RABBITMQ_CLIENT,
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.RMQ,
          options: {
            urls: [configService.get<string>(RABBITMQ_URI_KEY)],
            queue: configService.get<string>(RABBITMQ_AUTH_QUEUE_KEY),
            queueOptions: {
              durable: true,
            },
            noAck: false,
            persistent: true,
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [AuthServiceController], // Your gRPC controller
  providers: [AuthServiceService, JwtStrategy, Logger], // Your main service and Passport strategy
})
export class AuthServiceModule {}
