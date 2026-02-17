import {
  Controller,
  Get,
  Headers,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './strategy/local.strategy';
import { User } from 'src/user/entity/user.entity';
import { JwtAuthGuard } from './strategy/jwt.strategy';

interface AuthenticatedRequest extends Request {
  user: User;
}
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  // authorization: Basic $token
  registerUser(@Headers('authorization') token: string) {
    return this.authService.register(token);
  }

  @Post('login')
  // authorization: Basic $token
  loginUser(@Headers('authorization') token: string) {
    return this.authService.login(token);
  }

  @Post('token/access')
  async refreshAccessToken(@Request() req: AuthenticatedRequest) {
    return {
      accessToken: await this.authService.issueToken(req.user, false),
    };
  }

  @UseGuards(LocalAuthGuard)
  @Post('login/passport')
  async loginUserPassport(@Request() req: AuthenticatedRequest) {
    return {
      refreshToken: await this.authService.issueToken(req.user, true),
      accessToken: await this.authService.issueToken(req.user, false),
    };
  }

  // 어떤 사용자만 사용 가능한지를 정의
  // 토큰을 기반으로 확인
  @UseGuards(JwtAuthGuard)
  @Get('private')
  private(@Request() req: AuthenticatedRequest) {
    return req.user;
  }
}
