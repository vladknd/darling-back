import { NestFactory } from '@nestjs/core';
import { AuthServiceModule } from './auth-service.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AUTH_PACKAGE_NAME } from '@app/proto-definitions/auth'; // Generated from auth.proto
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common'; // Import ValidationPipe

async function bootstrap() {
  // Create a temporary app context to access ConfigService for port, then close it.
  // This ensures ConfigModule is loaded and .env variables are available.
  const tempAppContext = await NestFactory.createApplicationContext(AuthServiceModule);
  const configService = tempAppContext.get(ConfigService);
  const port = configService.get<string>('AUTH_SERVICE_PORT', '50051'); // Default if not in .env
  await tempAppContext.close();

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AuthServiceModule,
    {
      transport: Transport.GRPC,
      options: {
        package: AUTH_PACKAGE_NAME,
        // Path relative to the compiled 'dist/apps/auth-service/main.js'
        protoPath: join(__dirname, '../../../../libs/proto-definitions/src/auth.proto'),
        url: `0.0.0.0:${port}`,
        loader: { // Recommended loader options for gRPC
          keepCase: true,     // Preserves field names as defined in .proto
          longs: String,      // JavaScript doesn't have native 64-bit integers, represent as strings
          enums: String,      // Represent enums as strings
          defaults: true,     // Set default values for missing fields
          oneofs: true,       // Represent oneof fields as virtual properties
        },
      },
    },
  );

  // Optional: Use global pipes for gRPC if you have DTOs with class-validator on @Payload
  // This is more relevant if your gRPC request messages are classes with decorators.
  // For proto-generated interfaces, validation is typically done in the service/controller.
  // app.useGlobalPipes(new ValidationPipe({
  //   whitelist: true, // Strip properties not in DTO
  //   transform: true,   // Transform payload to DTO instance
  //   exceptionFactory: (errors) => new RpcException(errors), // Convert validation errors to RpcException
  // }));

  const logger = new Logger('AuthServiceBootstrap');
  await app.listen();
  logger.log(`AuthService microservice is listening on gRPC port ${port}`);
}
bootstrap();
