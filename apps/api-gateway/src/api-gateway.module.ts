import { Module } from '@nestjs/common';
import { ApiGatewayController } from './api-gateway.controller';
import { ApiGatewayService } from './api-gateway.service';
import { PassportModule } from '@nestjs/passport'; // Add this
import { ConfigModule, ConfigService } from '@nestjs/config'; // Add this
import { GoogleStrategy, AUTH_SERVICE_GRPC } from './strategies/google.strategy'; // Import your new strategy
import { ClientsModule, Transport } from '@nestjs/microservices'; // Add this
import { AUTH_PACKAGE_NAME } from '@app/proto-definitions'; // Add this
import * as Joi from 'joi'; // Add this for validation

@Module({
  imports: [
    // Configure ConfigModule for environment variables
    ConfigModule.forRoot({
      isGlobal: true, // Make ConfigService available globally
      envFilePath: process.env.NODE_ENV === 'test' ? '.env.test' : '.env',
      ignoreEnvFile: process.env.NODE_ENV === 'production',
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
        PORT: Joi.number().default(3000), // Default HTTP port for API Gateway
        GOOGLE_CLIENT_ID: Joi.string().required(),
        GOOGLE_CLIENT_SECRET: Joi.string().required(),
        GOOGLE_CALLBACK_URL: Joi.string().uri().required(),
        AUTH_SERVICE_GRPC_URL: Joi.string().required(),
        AUTH_PACKAGE_NAME: Joi.string().required(),
      }),
      validationOptions: {
        allowUnknown: true,
        abortEarly: false,
      },
    }),
    PassportModule, // Initialize Passport
    ClientsModule.registerAsync([
      {
        name: AUTH_SERVICE_GRPC, // This token will be used to inject the client
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.GRPC,
          options: {
            url: configService.get<string>('AUTH_SERVICE_GRPC_URL'),
            package: AUTH_PACKAGE_NAME,
            protoPath: 'libs/proto-definitions/src/auth.proto', // Path relative to project root
            loader: {
              keepCase: true,
              longs: String,
              enums: String,
              defaults: true,
              oneofs: true,
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [ApiGatewayController],
  providers: [ApiGatewayService, GoogleStrategy], // Add GoogleStrategy here
})
export class ApiGatewayModule {}