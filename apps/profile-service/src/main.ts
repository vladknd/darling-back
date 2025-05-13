import { NestFactory } from '@nestjs/core';
import { ProfileServiceModule } from './profile-service.module';

async function bootstrap() {
  const app = await NestFactory.create(ProfileServiceModule);
  await app.listen(3000);
}
bootstrap();
