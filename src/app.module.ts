import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/user.entity';
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      port: 5432,
      username: "postgres",
      password: "1234",
      host: "127.0.0.1",
      database: 'auth',
      entities: [User],
      synchronize: true,
    }),
    MailerModule.forRoot({
      transport: {
        host: "sandbox.smtp.mailtrap.io",
        port: 2525,
        auth: {
          user: "fbe140f53c5e77",
          pass: "9611bfb33669b9"
        }
      },
      defaults: {
        from: '"No Reply" <noreply@example.com>'
      }
    }),
    AuthModule,
    UsersModule,
  ],
})
export class AppModule {}

