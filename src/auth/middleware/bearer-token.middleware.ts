import {
  BadRequestException,
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { NextFunction, Request, Response } from 'express';
import { envVariables } from 'src/common/constant/env.const';

@Injectable()
export class BearerTokenMiddleware implements NestMiddleware {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    // 'Basic $token'
    // 'Bearer $token'
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      // 인증을 할 의도가 없음
      next();
      return;
    }

    // 인증을 할 의도가 있음
    const token = this.validateBearerToken(authHeader);

    //jwtService.verifyAsync는 payload를 가져오는 동시에 검증까지 진행함
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const decodedPayload = this.jwtService.decode(token);

      if (
        decodedPayload.type !== 'refresh' &&
        decodedPayload.type !== 'access'
      ) {
        throw new BadRequestException('잘못된 토큰 형식입니다.');
      }

      const isRefreshToken = decodedPayload.type === 'refresh';

      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>(
          isRefreshToken
            ? envVariables.refreshTTokenSecret
            : envVariables.accessTokenSecret,
        ),
      });

      req.user = payload;
      next();
    } catch (e) {
      throw new UnauthorizedException('토큰이 만료되었습니다.');
    }
  }

  validateBearerToken(rawToken: string) {
    /// 1. rawToken을 ' ' 기준으로 split한 후 토큰 값만 추출
    const bearerSplit = rawToken.split(' ');

    if (bearerSplit.length !== 2) {
      throw new BadRequestException('토큰 포맷이 잘못되었습니다!');
    }
    const [bearer, token] = bearerSplit;

    if (bearer.toLowerCase() !== 'bearer') {
      throw new BadRequestException('토큰 포맷이 잘못되었습니다!');
    }

    return token;
  }
}
