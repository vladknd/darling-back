import { Test, TestingModule } from '@nestjs/testing';
import { ProfileServiceController } from './profile-service.controller';
import { ProfileServiceService } from './profile-service.service';

describe('ProfileServiceController', () => {
  let profileServiceController: ProfileServiceController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [ProfileServiceController],
      providers: [ProfileServiceService],
    }).compile();

    profileServiceController = app.get<ProfileServiceController>(ProfileServiceController);
  });

  describe('root', () => {
    it('should return "Hello World!"', () => {
      expect(profileServiceController.getHello()).toBe('Hello World!');
    });
  });
});
