import { NestFactory } from '@nestjs/core';
import { AuthServiceModule } from './auth-service.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AUTH_PACKAGE_NAME } from '@app/proto-definitions';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const tempAppContext = await NestFactory.createApplicationContext(AuthServiceModule);
  const configService = tempAppContext.get(ConfigService);
  const port = configService.get<string>('AUTH_SERVICE_PORT', '50051');
  
  // Corrected path relative to the final position of this file in `dist/apps/auth-service/`
  const protoPath = join(__dirname, '../../libs/proto-definitions/src/auth.proto');
  await tempAppContext.close();

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AuthServiceModule,
    {
      transport: Transport.GRPC,
      options: {
        package: AUTH_PACKAGE_NAME,
        protoPath: protoPath,
        url: `0.0.0.0:${port}`,
        loader: {
          keepCase: true,
          longs: String,
          enums: String,
          defaults: true,
          oneofs: true,
        },
      },
    },
  );

  const logger = new Logger('AuthServiceBootstrap');
  await app.listen();
  logger.log(`AuthService microservice is listening on gRPC port ${port}`);
}
bootstrap();