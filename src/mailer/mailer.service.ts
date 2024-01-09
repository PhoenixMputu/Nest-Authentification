import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private async transporter() {
    const testAccount = await nodemailer.createTestAccount();
    const transoirt = nodemailer.createTransport({
      host: 'localhost',
      port: 8025,
      ignoreTLS: true,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
    return transoirt;
  }

  async sendSignupConfirmation(userEmail: string) {
    (await this.transporter()).sendMail({
      from: 'app@localhost.com',
      to: userEmail,
      subject: 'Inscription',
      html: '<h3>Hello World!</h3>',
    });
  }

  async sendResetPassword(userEmail: string, url: string, code: string) {
    (await this.transporter()).sendMail({
      from: 'app@localhost.com',
      to: userEmail,
      subject: 'Reset password',
      html: `
        <a href="${url}">Reset Password</a>
        <p>Secret code <strong>${code}</strong></p>
        <p>Code will expire in 15 minutes</p>
      `,
    });
  }
}
