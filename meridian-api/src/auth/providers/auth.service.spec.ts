jest.mock('src/users/user.entity', () => ({ User: class User {} }), {
  virtual: true,
});

import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
jest.mock('../../audit/audit.service', () => ({ AuditService: class AuditService {} }));

describe('AuthService - email verification (issue #435)', () => {
  let service: AuthService;
  let signInProviders: { SignIn: jest.Mock };
  let refreshTokenProvider: {
    refreshToken: jest.Mock;
    logout: jest.Mock;
    logoutAll: jest.Mock;
  };
  let verifyEmailProvider: { verifyEmail: jest.Mock; issueVerificationToken: jest.Mock };
  let usersRepository: { findOne: jest.Mock };
  let auditService: { log: jest.Mock };

  const fakeUser: any = { id: 7, email: 'a@b.com' };

  beforeEach(() => {
    signInProviders = { SignIn: jest.fn() };
    refreshTokenProvider = {
      refreshToken: jest.fn(),
      logout: jest.fn(),
      logoutAll: jest.fn(),
    };
    verifyEmailProvider = { verifyEmail: jest.fn(), issueVerificationToken: jest.fn() };
    usersRepository = { findOne: jest.fn() };
    auditService = { log: jest.fn(async () => undefined) };

    service = new AuthService(
      signInProviders as any,
      refreshTokenProvider as any,
      verifyEmailProvider as any,
      usersRepository as any,
      auditService as any,
    );
  });

  describe('verifyEmail', () => {
    it('delegates to VerifyEmailProvider and returns the verified user', async () => {
      verifyEmailProvider.verifyEmail.mockResolvedValueOnce(fakeUser);

      await expect(service.verifyEmail('raw')).resolves.toEqual(fakeUser);
      expect(verifyEmailProvider.verifyEmail).toHaveBeenCalledWith('raw');
    });

    it('propagates errors from VerifyEmailProvider', async () => {
      verifyEmailProvider.verifyEmail.mockRejectedValueOnce(
        new UnauthorizedException('bad'),
      );

      await expect(service.verifyEmail('bad')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  describe('resendVerification', () => {
    it('returns an acknowledgement for an existing user', async () => {
      usersRepository.findOne.mockResolvedValueOnce(fakeUser);

      const result = await service.resendVerification(fakeUser.email);

      expect(usersRepository.findOne).toHaveBeenCalledWith({
        where: { email: fakeUser.email },
        withDeleted: false,
      });
      expect(verifyEmailProvider.issueVerificationToken).toHaveBeenCalledWith(fakeUser);
      expect(auditService.log).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'RESEND_VERIFICATION', entityId: fakeUser.id }),
      );
      expect(result).toMatchObject({ status: 'ok' });
    });

    it('returns the same acknowledgement for an unknown email (no enumeration)', async () => {
      usersRepository.findOne.mockResolvedValueOnce(null);

      const result = await service.resendVerification('ghost@example.com');

      expect(result).toMatchObject({ status: 'ok' });
    });

    it('returns the same acknowledgement for an already-verified user (idempotent)', async () => {
      usersRepository.findOne.mockResolvedValueOnce({
        ...fakeUser,
        emailVerified: true,
      });

      const result = await service.resendVerification(fakeUser.email);

      expect(result).toMatchObject({ status: 'ok' });
    });
  });

  describe('signIn', () => {
    it('delegates to SignIn provider and is idempotent with a request key', async () => {
      const credentials = { email: 'a@b.com', password: 'x' };
      const result = { token: 'abc' };
      signInProviders.SignIn.mockResolvedValue(result);

      const first = await (service as any).signIn(credentials, 'req-key');
      const second = await (service as any).signIn(credentials, 'req-key');

      expect(first).toEqual(result);
      expect(second).toEqual(result);
      expect(signInProviders.SignIn).toHaveBeenCalledTimes(1);
    });

    it('rejects conflicting reuse of a request key with different credentials', async () => {
      signInProviders.SignIn.mockResolvedValueOnce({ token: 'first' });
      await (service as any).signIn({ email: 'a@b.com' }, 'req-key');
      await expect(
        (service as any).signIn({ email: 'c@d.com' }, 'req-key'),
      ).rejects.toBeInstanceOf(ConflictException);
    });
  });

  describe('refreshToken', () => {
    it('delegates to RefreshTokenProvider and is idempotent with a request key', async () => {
      const result = { accessToken: 'new' };
      refreshTokenProvider.refreshToken.mockResolvedValue(result);

      const first = await (service as any).refreshToken('old-token', 'req-key');
      const second = await (service as any).refreshToken('old-token', 'req-key');

      expect(first).toEqual(result);
      expect(second).toEqual(result);
      expect(refreshTokenProvider.refreshToken).toHaveBeenCalledTimes(1);
    });

    it('rejects conflicting reuse of a request key with a different token', async () => {
      refreshTokenProvider.refreshToken.mockResolvedValueOnce({ accessToken: 'new' });
      await (service as any).refreshToken('old-token', 'req-key');
      await expect(
        (service as any).refreshToken('other-token', 'req-key'),
      ).rejects.toBeInstanceOf(ConflictException);
    });

    it('propagates provider rejection when a refresh token is replayed', async () => {
      refreshTokenProvider.refreshToken
        .mockResolvedValueOnce({ accessToken: 'new' })
        .mockRejectedValueOnce(new UnauthorizedException('replay detected'));

      await (service as any).refreshToken('same-token', 'key-1');
      await expect(
        (service as any).refreshToken('same-token', 'key-2'),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('delegates to RefreshTokenProvider.logout and is idempotent with a request key', async () => {
      refreshTokenProvider.logout.mockResolvedValue(undefined);

      await (service as any).logout('token', 'req-key');
      await (service as any).logout('token', 'req-key');

      expect(refreshTokenProvider.logout).toHaveBeenCalledTimes(1);
    });
  });

  describe('logoutAll', () => {
    it('delegates to RefreshTokenProvider.logoutAll and is idempotent with a request key', async () => {
      refreshTokenProvider.logoutAll.mockResolvedValue(undefined);

      await (service as any).logoutAll(7, 'req-key');
      await (service as any).logoutAll(7, 'req-key');

      expect(refreshTokenProvider.logoutAll).toHaveBeenCalledTimes(1);
    });
  });

  describe('verifyEmail idempotency', () => {
    it('is idempotent with a request key and rejects conflicting reuse', async () => {
      verifyEmailProvider.verifyEmail.mockResolvedValue(fakeUser);

      const first = await (service as any).verifyEmail('token', 'req-key');
      const second = await (service as any).verifyEmail('token', 'req-key');

      expect(first).toEqual(fakeUser);
      expect(second).toEqual(fakeUser);
      expect(verifyEmailProvider.verifyEmail).toHaveBeenCalledTimes(1);

      await expect(
        (service as any).verifyEmail('other-token', 'req-key'),
      ).rejects.toBeInstanceOf(ConflictException);
    });
  });

  describe('resendVerification idempotency', () => {
    it('is idempotent with a request key and rejects conflicting reuse', async () => {
      usersRepository.findOne.mockResolvedValue(fakeUser);

      const first = await (service as any).resendVerification(fakeUser.email, 'req-key');
      const second = await (service as any).resendVerification(fakeUser.email, 'req-key');

      expect(first).toMatchObject({ status: 'ok' });
      expect(second).toMatchObject({ status: 'ok' });
      expect(usersRepository.findOne).toHaveBeenCalledTimes(1);

      await expect(
        (service as any).resendVerification('other@example.com', 'req-key'),
      ).rejects.toBeInstanceOf(ConflictException);
    });
  });
});
