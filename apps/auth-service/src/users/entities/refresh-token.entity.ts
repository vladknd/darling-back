// File: ./your-dating-app-backend/apps/auth-service/src/users/entities/refresh-token.entity.ts
// Purpose: TypeORM entity for refresh_tokens table.
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, CreateDateColumn, Index } from 'typeorm';
import { UserCredential } from './user-credential.entity';

@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  // Foreign key column that will be created in the database.
  // TypeORM uses this to understand the relationship.
  @Column('uuid')
  userCredentialId: string;

  // Defines the many-to-one relationship.
  // The first argument is a lambda returning the target entity.
  // The second argument is a lambda that defines the inverse side of the relationship
  // (i.e., how RefreshToken instances are accessed from a UserCredential instance).
  @ManyToOne(() => UserCredential, (userCredential) => userCredential.refreshTokens, {
    onDelete: 'CASCADE', // If a UserCredential is deleted, all its RefreshTokens are also deleted.
    nullable: false,     // A RefreshToken must belong to a UserCredential.
  })
  @JoinColumn({ name: 'userCredentialId' }) // Explicitly define the FK column name in this table.
  userCredential: UserCredential; // This property allows you to access the related UserCredential object.

  @Index({ unique: true }) // Each refresh token string must be unique.
  @Column({ type: 'varchar', length: 512, unique: true, nullable: false })
  token: string; // The actual JWT refresh token string. Length should accommodate JWTs.

  @Column({ type: 'timestamp with time zone', nullable: false })
  expiresAt: Date; // When this specific refresh token instance expires.

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ type: 'boolean', default: false })
  isRevoked: boolean;

  // Optional: If implementing strict one-time use refresh token rotation,
  // you might store the token that replaced this one.
  @Column({ type: 'varchar', length: 512, nullable: true })
  replacedByToken: string | null;
}
