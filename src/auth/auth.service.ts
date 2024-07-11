import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // generate the new password
    const hashPassword = await argon.hash(dto.password);
    // then ssave the user in the db
    const user = this.prisma.user.create({
      data: {
        firstName: dto.firstName,
        lastName: dto.lastName,
        email: dto.email,
        password: hashPassword,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
      },
    });
    // then return the saved user

    return user;
  }

  signin() {
    return { msg: 'I am sign in' };
  }
}
