import { Controller, Post, UseGuards, Res } from '@nestjs/common';
import { Response } from 'express';

import { User } from 'src/users/schema/user.schema';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { CurrentUser } from './current-user.decorator';
import { AuthService } from './auth.service';
import { JwtRefreshAuthGuard } from './guards/jwt-refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UseGuards(LocalAuthGuard)
  async login(
    @CurrentUser() user: User,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.login(user, response);
  }

  @Post('logout')
  @UseGuards(JwtRefreshAuthGuard)
  async logout(@CurrentUser() user: User, @Res() response: Response) {
    try {
      return await this.authService.logout(user, response);
    } catch (error) {
      return response
        .status(error.getStatus())
        .json({ message: error.message });
    }
  }

  @Post('refresh')
  @UseGuards(JwtRefreshAuthGuard)
  async refreshToken(
    @CurrentUser() user: User,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.refresh(user, response);
  }
}
