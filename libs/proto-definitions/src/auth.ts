// Code generated by protoc-gen-ts_proto. DO NOT EDIT.
// versions:
//   protoc-gen-ts_proto  v2.7.0
//   protoc               v6.31.1
// source: auth.proto

/* eslint-disable */
import { BinaryReader, BinaryWriter } from "@bufbuild/protobuf/wire";
import { type handleUnaryCall, type UntypedServiceImplementation } from "@grpc/grpc-js";
import { GrpcMethod, GrpcStreamMethod } from "@nestjs/microservices";
import { Observable } from "rxjs";

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface RegisterResponse {
  userId: string;
  message: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  userId: string;
  verificationStatus: string;
}

export interface RefreshAccessTokenRequest {
  refreshToken: string;
}

export interface UserIdRequest {
  userId: string;
}

export interface VerificationStatusResponse {
  userId: string;
  status: string;
}

export interface ProcessIdvWebhookRequest {
  userId: string;
  newStatus: string;
  idvProviderReference: string;
  details: string;
}

export interface ProcessIdvWebhookResponse {
  success: boolean;
  message: string;
}

export interface ValidateAccessTokenRequest {
  accessToken: string;
}

export interface ValidateAccessTokenResponse {
  userId: string;
  email: string;
  verificationStatus: string;
  isValid: boolean;
  roles: string[];
  exp: number;
  iat: number;
}

function createBaseRegisterRequest(): RegisterRequest {
  return { email: "", password: "" };
}

export const RegisterRequest: MessageFns<RegisterRequest> = {
  encode(message: RegisterRequest, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.email !== "") {
      writer.uint32(10).string(message.email);
    }
    if (message.password !== "") {
      writer.uint32(18).string(message.password);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): RegisterRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseRegisterRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.email = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.password = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseRegisterResponse(): RegisterResponse {
  return { userId: "", message: "" };
}

export const RegisterResponse: MessageFns<RegisterResponse> = {
  encode(message: RegisterResponse, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.userId !== "") {
      writer.uint32(10).string(message.userId);
    }
    if (message.message !== "") {
      writer.uint32(18).string(message.message);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): RegisterResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseRegisterResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.userId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.message = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseLoginRequest(): LoginRequest {
  return { email: "", password: "" };
}

export const LoginRequest: MessageFns<LoginRequest> = {
  encode(message: LoginRequest, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.email !== "") {
      writer.uint32(10).string(message.email);
    }
    if (message.password !== "") {
      writer.uint32(18).string(message.password);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): LoginRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.email = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.password = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseLoginResponse(): LoginResponse {
  return { accessToken: "", refreshToken: "", userId: "", verificationStatus: "" };
}

export const LoginResponse: MessageFns<LoginResponse> = {
  encode(message: LoginResponse, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.accessToken !== "") {
      writer.uint32(10).string(message.accessToken);
    }
    if (message.refreshToken !== "") {
      writer.uint32(18).string(message.refreshToken);
    }
    if (message.userId !== "") {
      writer.uint32(26).string(message.userId);
    }
    if (message.verificationStatus !== "") {
      writer.uint32(34).string(message.verificationStatus);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): LoginResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.accessToken = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.refreshToken = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }

          message.userId = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }

          message.verificationStatus = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseRefreshAccessTokenRequest(): RefreshAccessTokenRequest {
  return { refreshToken: "" };
}

export const RefreshAccessTokenRequest: MessageFns<RefreshAccessTokenRequest> = {
  encode(message: RefreshAccessTokenRequest, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.refreshToken !== "") {
      writer.uint32(10).string(message.refreshToken);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): RefreshAccessTokenRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseRefreshAccessTokenRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.refreshToken = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseUserIdRequest(): UserIdRequest {
  return { userId: "" };
}

export const UserIdRequest: MessageFns<UserIdRequest> = {
  encode(message: UserIdRequest, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.userId !== "") {
      writer.uint32(10).string(message.userId);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): UserIdRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseUserIdRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.userId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseVerificationStatusResponse(): VerificationStatusResponse {
  return { userId: "", status: "" };
}

export const VerificationStatusResponse: MessageFns<VerificationStatusResponse> = {
  encode(message: VerificationStatusResponse, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.userId !== "") {
      writer.uint32(10).string(message.userId);
    }
    if (message.status !== "") {
      writer.uint32(18).string(message.status);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): VerificationStatusResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseVerificationStatusResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.userId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.status = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseProcessIdvWebhookRequest(): ProcessIdvWebhookRequest {
  return { userId: "", newStatus: "", idvProviderReference: "", details: "" };
}

export const ProcessIdvWebhookRequest: MessageFns<ProcessIdvWebhookRequest> = {
  encode(message: ProcessIdvWebhookRequest, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.userId !== "") {
      writer.uint32(10).string(message.userId);
    }
    if (message.newStatus !== "") {
      writer.uint32(18).string(message.newStatus);
    }
    if (message.idvProviderReference !== "") {
      writer.uint32(26).string(message.idvProviderReference);
    }
    if (message.details !== "") {
      writer.uint32(34).string(message.details);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): ProcessIdvWebhookRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseProcessIdvWebhookRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.userId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.newStatus = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }

          message.idvProviderReference = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }

          message.details = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseProcessIdvWebhookResponse(): ProcessIdvWebhookResponse {
  return { success: false, message: "" };
}

export const ProcessIdvWebhookResponse: MessageFns<ProcessIdvWebhookResponse> = {
  encode(message: ProcessIdvWebhookResponse, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.success !== false) {
      writer.uint32(8).bool(message.success);
    }
    if (message.message !== "") {
      writer.uint32(18).string(message.message);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): ProcessIdvWebhookResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseProcessIdvWebhookResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 8) {
            break;
          }

          message.success = reader.bool();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.message = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseValidateAccessTokenRequest(): ValidateAccessTokenRequest {
  return { accessToken: "" };
}

export const ValidateAccessTokenRequest: MessageFns<ValidateAccessTokenRequest> = {
  encode(message: ValidateAccessTokenRequest, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.accessToken !== "") {
      writer.uint32(10).string(message.accessToken);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): ValidateAccessTokenRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseValidateAccessTokenRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.accessToken = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

function createBaseValidateAccessTokenResponse(): ValidateAccessTokenResponse {
  return { userId: "", email: "", verificationStatus: "", isValid: false, roles: [], exp: 0, iat: 0 };
}

export const ValidateAccessTokenResponse: MessageFns<ValidateAccessTokenResponse> = {
  encode(message: ValidateAccessTokenResponse, writer: BinaryWriter = new BinaryWriter()): BinaryWriter {
    if (message.userId !== "") {
      writer.uint32(10).string(message.userId);
    }
    if (message.email !== "") {
      writer.uint32(18).string(message.email);
    }
    if (message.verificationStatus !== "") {
      writer.uint32(26).string(message.verificationStatus);
    }
    if (message.isValid !== false) {
      writer.uint32(32).bool(message.isValid);
    }
    for (const v of message.roles) {
      writer.uint32(42).string(v!);
    }
    if (message.exp !== 0) {
      writer.uint32(48).int64(message.exp);
    }
    if (message.iat !== 0) {
      writer.uint32(56).int64(message.iat);
    }
    return writer;
  },

  decode(input: BinaryReader | Uint8Array, length?: number): ValidateAccessTokenResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseValidateAccessTokenResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }

          message.userId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }

          message.email = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }

          message.verificationStatus = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }

          message.isValid = reader.bool();
          continue;
        }
        case 5: {
          if (tag !== 42) {
            break;
          }

          message.roles.push(reader.string());
          continue;
        }
        case 6: {
          if (tag !== 48) {
            break;
          }

          message.exp = longToNumber(reader.int64());
          continue;
        }
        case 7: {
          if (tag !== 56) {
            break;
          }

          message.iat = longToNumber(reader.int64());
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
};

export interface AuthServiceClient {
  register(request: RegisterRequest): Observable<RegisterResponse>;

  login(request: LoginRequest): Observable<LoginResponse>;

  refreshAccessToken(request: RefreshAccessTokenRequest): Observable<LoginResponse>;

  getVerificationStatus(request: UserIdRequest): Observable<VerificationStatusResponse>;

  processIdvWebhook(request: ProcessIdvWebhookRequest): Observable<ProcessIdvWebhookResponse>;

  validateAccessToken(request: ValidateAccessTokenRequest): Observable<ValidateAccessTokenResponse>;
}

export interface AuthServiceController {
  register(request: RegisterRequest): Promise<RegisterResponse> | Observable<RegisterResponse> | RegisterResponse;

  login(request: LoginRequest): Promise<LoginResponse> | Observable<LoginResponse> | LoginResponse;

  refreshAccessToken(
    request: RefreshAccessTokenRequest,
  ): Promise<LoginResponse> | Observable<LoginResponse> | LoginResponse;

  getVerificationStatus(
    request: UserIdRequest,
  ): Promise<VerificationStatusResponse> | Observable<VerificationStatusResponse> | VerificationStatusResponse;

  processIdvWebhook(
    request: ProcessIdvWebhookRequest,
  ): Promise<ProcessIdvWebhookResponse> | Observable<ProcessIdvWebhookResponse> | ProcessIdvWebhookResponse;

  validateAccessToken(
    request: ValidateAccessTokenRequest,
  ): Promise<ValidateAccessTokenResponse> | Observable<ValidateAccessTokenResponse> | ValidateAccessTokenResponse;
}

export function AuthServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = [
      "register",
      "login",
      "refreshAccessToken",
      "getVerificationStatus",
      "processIdvWebhook",
      "validateAccessToken",
    ];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const AUTH_SERVICE_NAME = "AuthService";

export type AuthServiceService = typeof AuthServiceService;
export const AuthServiceService = {
  register: {
    path: "/auth.AuthService/Register",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: RegisterRequest) => Buffer.from(RegisterRequest.encode(value).finish()),
    requestDeserialize: (value: Buffer) => RegisterRequest.decode(value),
    responseSerialize: (value: RegisterResponse) => Buffer.from(RegisterResponse.encode(value).finish()),
    responseDeserialize: (value: Buffer) => RegisterResponse.decode(value),
  },
  login: {
    path: "/auth.AuthService/Login",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: LoginRequest) => Buffer.from(LoginRequest.encode(value).finish()),
    requestDeserialize: (value: Buffer) => LoginRequest.decode(value),
    responseSerialize: (value: LoginResponse) => Buffer.from(LoginResponse.encode(value).finish()),
    responseDeserialize: (value: Buffer) => LoginResponse.decode(value),
  },
  refreshAccessToken: {
    path: "/auth.AuthService/RefreshAccessToken",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: RefreshAccessTokenRequest) =>
      Buffer.from(RefreshAccessTokenRequest.encode(value).finish()),
    requestDeserialize: (value: Buffer) => RefreshAccessTokenRequest.decode(value),
    responseSerialize: (value: LoginResponse) => Buffer.from(LoginResponse.encode(value).finish()),
    responseDeserialize: (value: Buffer) => LoginResponse.decode(value),
  },
  getVerificationStatus: {
    path: "/auth.AuthService/GetVerificationStatus",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: UserIdRequest) => Buffer.from(UserIdRequest.encode(value).finish()),
    requestDeserialize: (value: Buffer) => UserIdRequest.decode(value),
    responseSerialize: (value: VerificationStatusResponse) =>
      Buffer.from(VerificationStatusResponse.encode(value).finish()),
    responseDeserialize: (value: Buffer) => VerificationStatusResponse.decode(value),
  },
  processIdvWebhook: {
    path: "/auth.AuthService/ProcessIdvWebhook",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: ProcessIdvWebhookRequest) => Buffer.from(ProcessIdvWebhookRequest.encode(value).finish()),
    requestDeserialize: (value: Buffer) => ProcessIdvWebhookRequest.decode(value),
    responseSerialize: (value: ProcessIdvWebhookResponse) =>
      Buffer.from(ProcessIdvWebhookResponse.encode(value).finish()),
    responseDeserialize: (value: Buffer) => ProcessIdvWebhookResponse.decode(value),
  },
  validateAccessToken: {
    path: "/auth.AuthService/ValidateAccessToken",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: ValidateAccessTokenRequest) =>
      Buffer.from(ValidateAccessTokenRequest.encode(value).finish()),
    requestDeserialize: (value: Buffer) => ValidateAccessTokenRequest.decode(value),
    responseSerialize: (value: ValidateAccessTokenResponse) =>
      Buffer.from(ValidateAccessTokenResponse.encode(value).finish()),
    responseDeserialize: (value: Buffer) => ValidateAccessTokenResponse.decode(value),
  },
} as const;

export interface AuthServiceServer extends UntypedServiceImplementation {
  register: handleUnaryCall<RegisterRequest, RegisterResponse>;
  login: handleUnaryCall<LoginRequest, LoginResponse>;
  refreshAccessToken: handleUnaryCall<RefreshAccessTokenRequest, LoginResponse>;
  getVerificationStatus: handleUnaryCall<UserIdRequest, VerificationStatusResponse>;
  processIdvWebhook: handleUnaryCall<ProcessIdvWebhookRequest, ProcessIdvWebhookResponse>;
  validateAccessToken: handleUnaryCall<ValidateAccessTokenRequest, ValidateAccessTokenResponse>;
}

function longToNumber(int64: { toString(): string }): number {
  const num = globalThis.Number(int64.toString());
  if (num > globalThis.Number.MAX_SAFE_INTEGER) {
    throw new globalThis.Error("Value is larger than Number.MAX_SAFE_INTEGER");
  }
  if (num < globalThis.Number.MIN_SAFE_INTEGER) {
    throw new globalThis.Error("Value is smaller than Number.MIN_SAFE_INTEGER");
  }
  return num;
}

interface MessageFns<T> {
  encode(message: T, writer?: BinaryWriter): BinaryWriter;
  decode(input: BinaryReader | Uint8Array, length?: number): T;
}
