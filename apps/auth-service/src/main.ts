import { NestFactory } from '@nestjs/core';
import { AuthServiceModule } from './auth-service.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AUTH_PACKAGE_NAME } from '@app/proto-definitions/auth';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AuthServiceModule,
    {
      transport: Transport.GRPC,
      options: {
        package: AUTH_PACKAGE_NAME,
        protoPath: join(
          __dirname,
          '../../../libs/proto-definitions/src/auth.proto',
        ),
        url: '0.0.0.0:50051',
      },
    },
  );
  await app.listen();
  console.log('AuthService microservice is listening on port 50051');
}
bootstrap();
