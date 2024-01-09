import { Injectable } from '@nestjs/common';
import {
  ConflictException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common/exceptions';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import { SignupDto } from './dto/signupDto';
import { SigninDto } from './dto/signinDto';
import { PrismaService } from 'src/prisma/prisma.service';
import { MailerService } from 'src/mailer/mailer.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmationDto';
import { DeleteAccountDto } from './dto/deleteAccountDto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly emailService: MailerService,
    private readonly JwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signup(signupDto: SignupDto) {
    const { email, username, password } = signupDto;
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (user) throw new ConflictException('User already exists');
    const hash = await bcrypt.hash(password, 10);
    await this.prismaService.user.create({
      data: { email, username, password: hash },
    });
    await this.emailService.sendSignupConfirmation(email);
    return {
      data: 'User succesfully created !',
    };
  }

  async signin(signinDto: SigninDto) {
    const { email, password } = signinDto;

    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('Password does not match');
    const payload = {
      sub: user.userID,
      email: user.email,
    };
    const token = this.JwtService.sign(payload, {
      expiresIn: '2h',
      secret: this.configService.get('SECRET_KEY'),
    });

    return {
      token,
      user: {
        username: user.username,
        email: user.email,
      },
    };
  }

  async resetPassword(resetPasswordDemandDto: ResetPasswordDemandDto) {
    const { email } = resetPasswordDemandDto;
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');
    const code = speakeasy.totp({
      secret: this.configService.get('OTP_CODE')!,
      digits: 5,
      step: 60 * 15,
      encoding: 'base32',
    });
    const url = 'http://localhost:300/reset-password-confirmation';
    await this.emailService.sendResetPassword(email, url, code);
    return { data: 'Reset password mail has been sent' };
  }

  async resetPasswordConfirmation(
    resetPasswordConfirmation: ResetPasswordConfirmationDto,
  ) {
    const { email, code, password } = resetPasswordConfirmation;
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');
    const match = speakeasy.totp.verify({
      secret: this.configService.get('OTP_CODE')!,
      digits: 5,
      step: 60 * 15,
      encoding: 'base32',
      token: code,
    });
    if (!match) throw new UnauthorizedException('Invalid/expired token');
    const hash = await bcrypt.hash(password, 10);
    await this.prismaService.user.update({
      where: { email },
      data: { password: hash },
    });
    return { data: 'Password updated successfully' };
  }

  async deleteAccount(userID: any, deleteAccountDto: DeleteAccountDto) {
    const { password } = deleteAccountDto;
    const user = await this.prismaService.user.findUnique({
      where: { userID },
    });
    if (!user) throw new NotFoundException('User not found');
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('Password does not match');
    await this.prismaService.user.delete({ where: { userID } });
    return { data: 'User successfully deleted' };
  }
}
