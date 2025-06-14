// File: ./your-dating-app-backend/apps/auth-service/src/users/entities/refresh-token.entity.ts
// Purpose: TypeORM entity for refresh_tokens table.
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, CreateDateColumn, Index } from 'typeorm';
import { UserCredential } from './user-credential.entity';

@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userCredentialId: string;

  @ManyToOne(() => UserCredential, (userCredential) => userCredential.refreshTokens, {
    onDelete: 'CASCADE',
    nullable: false,
  })
  @JoinColumn({ name: 'userCredentialId' })
  userCredential: UserCredential;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 512, unique: true, nullable: false })
  token: string;

  @Column({ type: 'timestamp with time zone', nullable: false })
  expiresAt: Date;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ type: 'boolean', default: false })
  isRevoked: boolean;

  @Column({ type: 'varchar', length: 512, nullable: true })
  replacedByToken: string | null;
}
