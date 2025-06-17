// File: ./your-dating-app-backend/jest.config.js
// Purpose: Centralized Jest configuration for the monorepo.

/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
    // A map from regular expressions to module names or to arrays of module names that allow to stub out resources with a single module
    moduleNameMapper: {
      // This uses the paths defined in your tsconfig.json for Jest
      // It's crucial for monorepo path aliases like @app/*
      '^@app/common(|/.*)$': '<rootDir>/libs/common/src/$1',
      '^@app/proto-definitions(|/.*)$': '<rootDir>/libs/proto-definitions/src/$1',
      '^@bufbuild/protobuf/wire$': '@bufbuild/protobuf',
    },
  
    // A preset that is used as a base for Jest's configuration
    preset: 'ts-jest',
  
    // The test environment that will be used for testing
    testEnvironment: 'node',
  
    // A map from regular expressions to paths to transformers
    transform: {
      '^.+\\.(t|j)s$': 'ts-jest',
    },
  
    // The glob patterns Jest uses to detect test files
    testRegex: '.*\\.spec\\.ts$',
  
    // An array of directory names to be searched recursively up from the requiring module's location
    moduleDirectories: ['node_modules', '<rootDir>'],
  
    // The root directory that Jest should scan for tests and modules within
    rootDir: '.',
  
    // An array of glob patterns indicating a set of files for which coverage information should be collected
    collectCoverageFrom: ['**/*.(t|j)s'],
  
    // The directory where Jest should output its coverage files
    coverageDirectory: './coverage',
  };
  