import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';
import { ConfigModule } from '@nestjs/config';
import Joi from 'joi';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        HASH_ROUNDS: Joi.number().required(),
        ACCESS_TOKEN_SECRET: Joi.string().required(),
        REFRESH_TOKEN_SECRET: Joi.string().required(),
      }),
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'postgres', // 본인의 DB 계정
      password: 'postgres', // 본인의 DB 비밀번호
      database: 'postgres', // 본인의 DB 이름
      entities: [__dirname + '/**/*.entity{.ts,.js}'],

      // synchronize: true는 엔티티와 DB 스키마를 자동으로 동기화합니다.
      // 개발 환경에서는 편하지만, 운영(Production) 환경에서는 false로 바꿔야 안전합니다.
      synchronize: true,
    }),
    AuthModule,
    UserModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
