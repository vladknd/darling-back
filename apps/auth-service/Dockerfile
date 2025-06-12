# File: ./your-dating-app-backend/apps/auth-service/Dockerfile
# Purpose: Dockerfile for auth-service, focused on a development environment with hot-reloading.

# Stage 1: Base Image
# Use an official Node.js image with version 20 or higher, as required by NestJS v10+.
# The '-alpine' variant is smaller, which is good for image size.
FROM node:20-alpine

# Set the working directory inside the container. All subsequent commands will be run from this directory.
WORKDIR /usr/src/app

# Copy root package files and yarn.lock FIRST.
# This leverages Docker's layer caching. If these files don't change between builds,
# Docker won't re-run the lengthy `yarn install` step, speeding up subsequent builds.
COPY package.json yarn.lock ./

# If your monorepo setup uses Yarn Workspaces with more configuration (e.g., .yarnrc.yml), copy that too.
# COPY .yarnrc.yml ./

# Install ALL dependencies (including devDependencies).
# For a development image using watch mode (`nest start --watch`), devDependencies
# like typescript, ts-node, and @nestjs/cli are required.
# `--frozen-lockfile` is a best practice to ensure the exact versions from yarn.lock are installed.
RUN yarn install --frozen-lockfile

# Copy the entire monorepo source code into the container.
# This is necessary so the auth-service can access shared libraries (e.g., libs/proto-definitions).
# It's crucial to have a `.dockerignore` file in your project root to prevent copying
# unnecessary files like the host's node_modules, .git folder, .env files, and dist folders.
COPY . .

# Document that the service inside the container is intended to listen on this port.
# The actual port mapping to the host machine is configured in docker-compose.yml.
EXPOSE 50051

# Set the environment to development. This can be used by your application logic
# (e.g., in auth-service.module.ts) to enable features like detailed logging or schema synchronization.
ENV NODE_ENV=development

# The command that will be run when the container starts.
# It uses the existing "start:dev" script from your package.json and passes
# "auth-service" as an argument to it. This resolves to `nest start auth-service --watch`.
#
# --- THIS LINE IS THE FIX ---
CMD ["yarn", "start:dev", "auth-service"]
