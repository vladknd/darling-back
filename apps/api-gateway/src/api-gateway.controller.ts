import { Controller, Get, Req, Res, UseGuards, HttpStatus, Logger } from '@nestjs/common'; // Add Req, Res, UseGuards, HttpStatus
import { ApiGatewayService } from './api-gateway.service';
import { AuthGuard } from '@nestjs/passport'; // Add AuthGuard
import { Response } from 'express'; // Import Response from express for redirect

@Controller()
export class ApiGatewayController {
  private readonly logger = new Logger(ApiGatewayController.name);

  constructor(private readonly apiGatewayService: ApiGatewayService) {}

  @Get()
  getHello(): string {
    return this.apiGatewayService.getHello();
  }

  // ----------------------------------------------------
  // Google OAuth Endpoints
  // ----------------------------------------------------

  @Get('/auth/google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req) {
    // This route initiates the Google OAuth flow.
    // Passport will redirect to Google's authentication page.
    this.logger.log('Initiating Google OAuth flow...');
    // The actual redirect is handled by Passport
  }

  @Get('/auth/google/redirect')
  @UseGuards(AuthGuard('google')) // 'google' strategy handles the callback
  async googleAuthRedirect(@Req() req, @Res() res: Response) {
    // This route handles the callback from Google.
    // req.user will contain the user object returned by GoogleStrategy.validate()
    this.logger.log(`Google OAuth callback received for user: ${req.user.email}`);

    if (!req.user) {
      this.logger.error('Google authentication failed: No user data received.');
      // Handle error: Redirect to an error page or return an error response
      return res.status(HttpStatus.UNAUTHORIZED).json({ message: 'Google authentication failed.' });
    }

    // From req.user, you will get the userId, email, and tokens from your auth-service
    // You can now redirect the user to your front-end application with these tokens,
    // or return them in the response.
    this.logger.log(`User logged in via Google: ${req.user.userId}`);

    // Example: Redirect to a success page with tokens as query params (for web)
    // In a real application, you might use cookies or a more secure method.
    const redirectUrl = `http://localhost:4200/auth/success?accessToken=${req.user.accessToken}&refreshToken=${req.user.refreshToken}&userId=${req.user.userId}`;
    res.redirect(redirectUrl);

    // Or, if you want to return JSON directly (e.g., for mobile/SPA that handles redirect)
    res.status(HttpStatus.OK).json({
      message: 'Google authentication successful',
      user: req.user,
    });
  }
}