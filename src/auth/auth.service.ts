import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { access } from 'fs';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    try {
      const hashPassword = await argon.hash(dto.password);
      // then ssave the user in the db
      const existUser = await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
      if (existUser) {
        throw new ForbiddenException('User already exists!!');
      } else {
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
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credential taken');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find the user by email

    const { email, password } = dto;

    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    // if user does not exist throw exception

    if (!user)
      throw new ForbiddenException('User does exists, please signup first!!!');

    // compare password

    const compared = await argon.verify(user.password, password);

    // if password incorrect throw exception
    if (!compared) throw new ForbiddenException('Your password is correct!!!');

    // send back the user
    delete user.password;
    return {
      access_token: await this.signToken(user.id, email),
      id: user.id,
      email: user.email,
    };
  }

  // sign token
  signToken(id: number, email: string) {
    const payload = {
      sub: id,
      email,
    };

    return this.jwtService.signAsync(payload, {
      expiresIn: '90d',
      secret: this.config.get('JWT_SECRET'),
    });
  }
}
