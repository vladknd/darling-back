// File: ./your-dating-app-backend/apps/auth-service/src/users/entities/user-credential.entity.ts
// Purpose: TypeORM entity for user_credentials table.
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany, Index } from 'typeorm';
import { RefreshToken } from './refresh-token.entity';

// Enum for verification status
export enum VerificationStatus {
  UNVERIFIED = 'UNVERIFIED',
  PENDING = 'PENDING',    // e.g., IDV submitted, awaiting result
  VERIFIED = 'VERIFIED',
  FAILED = 'FAILED',      // e.g., IDV failed
  REJECTED = 'REJECTED',  // e.g., Admin rejected or system rule
}

@Entity('user_credentials') // Specifies the table name
export class UserCredential {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index({ unique: true }) // Ensure email is unique and indexed for fast lookups
  @Column({ type: 'varchar', length: 255, unique: true, nullable: false })
  email: string;

  @Column({ type: 'varchar', length: 255, nullable: false, select: false }) // select: false hides it from default queries
  passwordHash: string;

  @Column({
    type: 'enum',
    enum: VerificationStatus,
    default: VerificationStatus.UNVERIFIED,
    nullable: false,
  })
  verificationStatus: VerificationStatus;

  // Defines the one-to-many relationship with RefreshToken
  // 'refreshToken.userCredential' refers to the 'userCredential' property in the RefreshToken entity
  // cascade: true means operations like save on UserCredential can cascade to its refreshTokens.
  // Be careful with cascade on delete; here, onDelete: 'CASCADE' is on the ManyToOne side in RefreshToken.
  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.userCredential, { cascade: ['insert', 'update'] })
  refreshTokens: RefreshToken[];

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'CURRENT_TIMESTAMP', onUpdate: 'CURRENT_TIMESTAMP' })
  updatedAt: Date;
}
