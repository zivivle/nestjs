import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import Joi from 'joi';
import { envVariables } from './common/constant/env.const';
import { BearerTokenMiddleware } from './auth/middleware/bearer-token.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        [envVariables.hashRounds]: Joi.number().required(),
        [envVariables.accessTokenSecret]: Joi.string().required(),
        [envVariables.refreshTTokenSecret]: Joi.string().required(),
        [envVariables.dbType]: Joi.string().required(),
        [envVariables.dbHost]: Joi.string().required(),
        [envVariables.dbPort]: Joi.number().required(),
        [envVariables.dbUsername]: Joi.string().required(),
        [envVariables.dbPassword]: Joi.string().required(),
        [envVariables.dbDatabase]: Joi.string().required(),
      }),
    }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: configService.get<string>(envVariables.dbType) as 'postgres',
        host: configService.get<string>(envVariables.dbHost),
        port: configService.get<number>(envVariables.dbPort),
        username: configService.get<string>(envVariables.dbUsername),
        password: configService.get<string>(envVariables.dbPassword),
        database: configService.get<string>(envVariables.dbDatabase),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        // 환경에 따라 동기화 여부 결정 (생산 환경은 무조건 false)
        synchronize: configService.get<string>('NODE_ENV') === 'development',
      }),
    }),
    AuthModule,
    UserModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(BearerTokenMiddleware)
      .exclude(
        { path: 'auth/login', method: RequestMethod.POST },
        { path: 'auth/register', method: RequestMethod.POST },
      )
      .forRoutes('*');
  }
}
