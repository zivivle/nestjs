import { BadRequestException, Injectable } from '@nestjs/common';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  parseBasicToken(rawToken: string) {
    /// 1. rawToken을 ' ' 기준으로 split한 후 토큰 값만 추출
    const basicSplit = rawToken.split(' ');

    if (basicSplit.length !== 2) {
      throw new BadRequestException('토큰 포맷이 잘못되었습니다!');
    }
    const [, token] = basicSplit;

    /// 2. 추출한 토큰을 base64로 디코딩해서 이메일과 비밀번호로 나눈다.
    /// 'utf-8' << 우리 실제로 쓰는 문자
    const decode = Buffer.from(token, 'base64').toString('utf-8');

    /// "email:password"
    const decodeSplit = decode.split(':');

    if (decodeSplit.length !== 2) {
      throw new BadRequestException('토큰 포맷이 잘못되었습니다!');
    }

    const [email, password] = decodeSplit;
    return {
      email,
      password,
    };
  }

  /// rawToken -> "Basic $token" 형식이다
  async register(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    // 체크: 회원 가입하려고 하는 사용자가 이미 가입한 사용자인지 체크
    const user = await this.userRepository.findOne({
      where: {
        email,
      },
    });

    if (user) {
      throw new BadRequestException('이미 가입한 이메일입니다!');
    }

    const hash = await bcrypt.hash(
      password,
      this.configService.get<number>('HASH_ROUNDS')!,
    );

    await this.userRepository.save({
      email,
      password: hash,
    });

    const newUser = await this.userRepository.findOne({
      where: {
        email,
      },
    });

    return newUser;
  }

  async login(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.userRepository.findOne({
      where: {
        email,
      },
    });

    if (!user) {
      throw new BadRequestException('잘못된 로그인 정보입니다!');
    }

    // passOk는 정확한 비밀번호가 맞는지 비교할때 사용됨
    // compare가 암호화되지 않은 password 전달 값과 암호화된 user정보에 저장된 password 값을 비교해줌
    const passOk = await bcrypt.compare(password, user.password);

    if (!passOk) {
      throw new BadRequestException('잘못된 로그인 정보입니다!');
    }

    const refreshTokenSecret = this.configService.get<string>(
      'REFRESH_TOKEN_SECRET',
    );
    const accessTokenSecret = this.configService.get<string>(
      'ACCESS_TOKEN_SECRET',
    );

    return {
      refreshToken: await this.jwtService.signAsync(
        {
          sub: user.id,
          role: user.role,
          type: 'refresh',
        },
        {
          secret: refreshTokenSecret,
          expiresIn: '24h',
        },
      ),
      accessToken: await this.jwtService.signAsync(
        {
          sub: user.id,
          role: user.role,
          type: 'access',
        },
        {
          secret: accessTokenSecret,
          // 5분
          expiresIn: 300,
        },
      ),
    };
  }
}
