import { Body, Controller, Delete, Post, Req, UseGuards } from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { SigninDto } from './dto/signinDto';
import { AuthService } from './auth.service';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmationDto';
import { AuthGuard } from '@nestjs/passport';
import { DeleteAccountDto } from './dto/deleteAccountDto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto);
  }

  @Post('signin')
  signin(@Body() signinDto: SigninDto) {
    return this.authService.signin(signinDto);
  }

  @Post('reset-password')
  resetPassword(@Body() resetPasswordDemandDto: ResetPasswordDemandDto) {
    return this.authService.resetPassword(resetPasswordDemandDto);
  }

  @Post('reset-password-confirmation')
  resetPasswordConfirmation(
    @Body() resetPasswordConfirmationDto: ResetPasswordConfirmationDto,
  ) {
    return this.authService.resetPasswordConfirmation(
      resetPasswordConfirmationDto,
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('delete')
  deleteAccount(@Req() request: any, @Body() deleteAccountDto: DeleteAccountDto) {
    const userID = request.user.userID;
    return this.authService.deleteAccount(userID, deleteAccountDto)
  }
}
