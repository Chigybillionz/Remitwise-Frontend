import { Injectable, Logger, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createHash } from 'crypto';
import { SignInDto } from '../dto/sign-in.dto';
import { SignInProviders } from './sign-in.providers';
import { RefreshTokenDto } from '../dto/refresh-token-dto';
import { RefreshTokenProvider } from './refreshToken.provider';
import { VerifyEmailProvider } from './verify-email.provider';
import { User } from 'src/users/user.entity';
import { AuditService } from '../../audit/audit.service';
import { AuditAction } from '../../audit/audit-log.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  /**
   * In-memory idempotency store.
   *
   * Binds each sensitive auth operation to a caller-supplied idempotency key.
   * When a key is provided:
   * - concurrent requests with the same key and same request hash share a single
   *   in-flight operation promise;
   * - retries after a success return the same response for a bounded TTl;
   * - reusing a key with a different request payload is rejected with a conflict.
   *
   * This is an in-process store. For horizontally scaled deployments it must be
   * replaced with a shared durable store (e.g. Redis) with equivalent semantics.
   */
  private readonly idempotencyStore = new Map<
    string,
    { requestHash: string; promise: Promise<unknown> }
  >();
  private readonly IDEMPOTENCY_TTL_MS = 5 * 60 * 1000; // 5 minutes

  constructor(
    //intra dependency injection of sigin Providers
    private readonly signInProviders: SignInProviders,

    private readonly refreshTokenProvider: RefreshTokenProvider,

    // Email-verification flow (issue #435): issues tokens and consumes them
    // when the recipient clicks the link from their signup mail.
    private readonly verifyEmailProvider: VerifyEmailProvider,

    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,

    private readonly auditService: AuditService,
  ) {}

  private hashRequest(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /**
   * Wraps an operation with idempotency key handling.
   *
   * When `ckey` is undefined or empty, the operation is executed directly.
   * Otherwise the key is bound to `requestHash`; conflicting reuse throws a
   * ConflictException and concurrent identical requests are deduplicated.
   */
  private async withIdempotency<T>(
    key: string | undefined,
    requestHash: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (!key) return operation();

    const existing = this.idempotencyStore.get(key);

    if (existing) {
      if (existing.requestHash !== requestHash) {
        throw new ConflictException(
          'Idempotency key used with a different request payload',
        );
      }
      return existing.promise as Promise<T>;
    }

    const promise = operation()
      .then((result) => {
        setTimeout(() => this.idempotencyStore.delete(key), this.IDEMPOTENCY_TTL_MS);
        return result;
      })
      .catch((error) => {
        this.idempotencyStore.delete(key);
        throw error;
      });

    this.idempotencyStore.set(key, { requestHash, promise });
    return promise;
  }

  public async SignIn(signInDto: SignInDto, idempotencyKey?: string) {
    return await this.withIdempotency(
      idempotencyKey,
      this.hashRequest(JSON.stringify(signInDto)),
      () => this.signInProviders.SignIn(signInDto),
    );
  }

  /**
   * Email-verification (issue #435): consume a raw verification token from
   * the signup mail. Delegates to VerifyEmailProvider for the heavy lifting
   * (lookup / match / cleanup).
   *
   * The verification token is used as an implicit idempotency key, so a replay
   * or concurrent submission of the same token is deduplicated for the TTL.
   */
  public async verifyEmail(token: string) {
    return await this.withIdempotency(
      `verifyEmail:${token}`,
      this.hashRequest(token),
      () => this.verifyEmailProvider.verifyEmail(token),
    );
  }

  /**
   * Email-verification (issue #435): re-issue a fresh verification token
   * for the given email if the account exists and is not already verified.
   * Always returns the same acknowledgement so callers cannot enumerate
   * which emails belong to a registered account.
   *
   * An optional `idempotencyKey` allows the caller to request at most one
   * reissue operation per key. Without a key, the operation retains its
   * existing behavior.
   */
  public async resendVerification(email: string, idempotencyKey?: string) {
    return await this.withIdempotency(
      idempotencyKey,
      this.hashRequest(email),
      () => this.resendVerificationInternal(email),
    );
  }

  private async resendVerificationInternal(email: string) {
    const user = await this.usersRepository.findOne({
      where: { email },
      withDeleted: false,
    });

    if (user && !user.emailVerified) {
      try {
        await this.verifyEmailProvider.issueVerificationToken(user);

        await this.auditService.log({
          entityName: 'VerificationToken',
          entityId: user.id,
          action: AuditAction.RESEND_VERIFICATION,
          performedById: user.id,
          performedByEmail: user.email,
        });
      } catch (error) {
        this.logger.error(
          `Failed to reissue verification token for ${email}: ${
            error instanceof Error ? error.message : error
          }`,
        );
      }
    }

    return {
      status: 'ok',
      message:
        'If that email belongs to an unverified account, a new verification email has been sent.',
    };
  }

  public async RefreshToken(
    refreshTokendto: RefreshTokenDto,
    userAgent?: string,
    idempotencyKey?: string,
  ) {
    return await this.withIdempotency(
      idempotencyKey,
      this.hashRequest(JSON.stringify({ dto: refreshTokendto, userAgent })),
      () => this.refreshTokenProvider.refreshToken(refreshTokendto, userAgent),
    );
  }

  public async logout(refreshTokendto: RefreshTokenDto, idempotencyKey?: string) {
    return await this.withIdempotency(
      idempotencyKey,
      this.hashRequest(JSON.stringify(refreshTokendto)),
      () => this.refreshTokenProvider.logout(refreshTokendto),
    );
  }

  public async logoutAll(userId: number, idempotencyKey?: string) {
    return await this.withIdempotency(
      idempotencyKey,
      this.hashRequest(JSON.stringify({ userId })),
      () => this.refreshTokenProvider.logoutAll(userId),
    );
  }
}
