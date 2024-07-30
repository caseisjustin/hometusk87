import { Controller, Post, Body, Request, UseGuards, Get, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() body) {
    const { username, email, password } = body;
    return this.authService.register(username, email, password);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('reset-password')
  async resetPassword(@Body() body) {
    const { email, oldPassword, newPassword, confirmNewPassword } = body;
    return this.authService.resetPassword(email, oldPassword, newPassword, confirmNewPassword);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() body) {
    const { email } = body;
    return this.authService.forgotPassword(email);
  }

  @Post('verifypass')
  async verifyPassword(@Body() body, @Query() param){
    const { password, newPassword} = body
    const {token} = param
    console.log(token)
    return this.authService.confirmPassword(token, password, newPassword);
  }
kjk
  @Get('verify-email')
  async verifyAndConfirmEmail(@Query() body) {
    const { token } = body;
    return this.authService.verifyAndConfirmEmail(token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('renew-tokens')
  async renewTokens(@Request() req) {
    return this.authService.renewTokens(req.user);
  }
}
