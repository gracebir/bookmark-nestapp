import { IsEmail, IsEmpty, IsNotEmpty, IsString } from 'class-validator';

export class AuthDto {
  @IsString()
  firstName?: string;

  @IsString()
  lastName?: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
