import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // DTO에 정의되지 않은 값은 거름
      forbidNonWhitelisted: true, // DTO에 없는 값이 들어오면 에러 메세지 보냄
      transform: true, // ★ 이게 핵심! 컨트롤러에서 받는 데이터를 클래스 인스턴스로 자동 변환
    }),
  );
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
