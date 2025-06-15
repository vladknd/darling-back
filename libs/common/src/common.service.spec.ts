// File: ./your-dating-app-backend/libs/common/src/common.service.spec.ts
// Purpose: Corrected test for the default common service.

import { Test, TestingModule } from '@nestjs/testing';
import { CommonService } from './common.service';

describe('CommonService', () => {
  let service: CommonService;

  beforeEach(async () => {
    // This test should be very simple and is a good way to check if the
    // overall Jest and NestJS testing environment is working correctly.
    const module: TestingModule = await Test.createTestingModule({
      providers: [CommonService],
    }).compile();

    service = module.get<CommonService>(CommonService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
