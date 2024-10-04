import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcryptjs';
import { Response } from "express"

import { User } from 'src/users/schema/user.schema';
import { UsersService } from 'src/users/users.service';
import { TokenPayload } from './token-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: User, response: Response) {
    const { accessToken, refreshToken, expiresRefreshToken } =
      await this.generateTokens(user);

    await this.userService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    this.setRefreshTokenCookie(response, refreshToken, expiresRefreshToken);

    return this.sendLoginResponse(response, user, accessToken);
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
      await this.generateTokens(user);

    await this.userService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    this.setRefreshTokenCookie(response, refreshToken, expiresRefreshToken);

    return this.sendLoginResponse(response, user, accessToken);
  }

  async verifyUserRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.userService.getUser({ _id: userId });
      const authenticated = await compare(refreshToken, user.refreshToken);

      if (!authenticated) {
        throw new UnauthorizedException();
      }

      return user;
    } catch (error) {
      throw new UnauthorizedException('Refresh token is not valid.');
    }
  }

  private async generateTokens(user: User) {
     
    const expiresRefreshToken = new Date(
      Date.now() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_REFRESH_TOKEN_EXPIRATION_MS',
          ),
        ),
    );

    const tokenPayload: TokenPayload = { userId: user._id.toHexString() };

    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS')}ms`,
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS')}ms`,
    });

    return { accessToken, refreshToken, expiresRefreshToken };
  }

  private setRefreshTokenCookie(
    response: Response,
    refreshToken: string,
    expiresRefreshToken: Date,
  ) {
    response.cookie('Refresh', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresRefreshToken,
    });
  }

  private sendLoginResponse(
    response: Response,
    user: User,
    accessToken: string,
  ) {
    return response.status(200).json({
      user: {
        id: user._id,
        email: user.email,
      },
      accessToken,
    });
  }
}
