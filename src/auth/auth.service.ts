import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcryptjs';
import { Response, Request } from 'express';

import { User } from 'src/users/schema/user.schema';
import { UsersService } from 'src/users/users.service';
import { TokenPayload } from './token-payload.interface';
import { TokenUtils } from './utils/token.utils';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly tokenUtils: TokenUtils,
  ) {}

  async login(user: User, response: Response) {
    const { accessToken, refreshToken, expiresRefreshToken } =
       this.tokenUtils.generateTokens(user);

    await this.userService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    this.tokenUtils.setRefreshTokenCookie(
      response,
      refreshToken,
      expiresRefreshToken,
    );

    return response.status(200).json({
      user: {
        id: user._id,
        email: user.email,
      },
      accessToken,
    });
  }

  async logout(user: User, response: Response) {
    try {
      const existingUser = await this.userService.getUser({ _id: user._id });
      if (!existingUser) {
        throw new UnauthorizedException('User not found.');
      }

      await this.userService.updateUser(
        { _id: user._id },
        { $unset: { refreshToken: '' } },
      );

      this.tokenUtils.clearRefreshTokenCookie(response);

      return {
        success: true,
        message: 'Logged out successfully',
      };
    } catch (error) {
      console.error('Logout error:', error);
      throw new UnauthorizedException('Logout failed.');
    }
  }

  async verifyUser(email: string, password: string) {
    try {
      const user = await this.userService.getUser({ email });

      const authenticated = await compare(password, user.password);

      if (!authenticated) {
        throw new UnauthorizedException('Email or password is incorrect.');
      }

      return user;
    } catch (error) {
      throw new UnauthorizedException('Email or password is incorrect.');
    }
  }

  async refresh(user: User, response: Response) {
    const { accessToken, refreshToken, expiresRefreshToken } =
      this.tokenUtils.generateTokens(user);

    await this.userService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    this.tokenUtils.setRefreshTokenCookie(
      response,
      refreshToken,
      expiresRefreshToken,
    );

    return response.status(200).json({
      user: {
        id: user._id,
        email: user.email,
      },
      accessToken,
    });
  }

  async verifyUserRefreshToken(request: Request, userId: string) {
    try {
      const refreshToken = request.cookies?.Refresh;

      if (!refreshToken) {
        throw new UnauthorizedException('No refresh token found.');
      }

      const user = await this.userService.getUser({ _id: userId });
      if (!user) {
        throw new UnauthorizedException('User not found.');
      }
    } catch (error) {
      throw new UnauthorizedException('Refresh token is not valid.');
    }
  }
}
