# File: ./your-dating-app-backend/apps/auth-service/Dockerfile
# Purpose: Dockerfile for auth-service (development focus with hot-reloading using Yarn)

FROM node:20-alpine # Use Node 20+
WORKDIR /usr/src/app

# Copy root package files and yarn.lock FIRST to leverage Docker layer caching
# These files define all dependencies for the monorepo.
COPY package.json yarn.lock ./
# If your monorepo setup requires other root files for 'yarn install' (e.g. .yarnrc.yml for Yarn Berry):
# COPY .yarnrc.yml ./
# COPY .pnp.cjs .pnp.loader.mjs ./ # For Yarn PnP

# Install ALL dependencies (including devDependencies for watch mode and ts-node)
# using Yarn. This will install for all workspaces in the monorepo.
RUN yarn install --frozen-lockfile

# Copy the entire monorepo source code.
# A .dockerignore file in your project root is highly recommended
# to exclude host node_modules, .git, host dist folders, .env files etc.
COPY . .

# The port the gRPC service inside the container will listen on
# This EXPOSE is for documentation; actual port mapping is in docker-compose.yml
# It's good practice to match the port your service will listen on.
EXPOSE 50051

ENV NODE_ENV=development

# Ensure your package.json has a script like:
# "scripts": {
#   "start:dev:auth": "nest start auth-service --watch --preserveWatchOutput"
# }
# This command will be run when the container starts.
CMD ["yarn", "start:dev:auth"]
