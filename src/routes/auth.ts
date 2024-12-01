import { Elysia, t } from "elysia";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
// import nodemailer from "nodemailer";

import { config } from "../config";
import prisma from "../utils/prisma";
import { Resend } from "resend";
import { logger } from "..";

// Utility Functions
const generateToken = (payload: any, secret: string, expiresIn: string) => {
  return jwt.sign(payload, secret, { expiresIn });
};

// const sendVerificationEmail = async (email: string, token: string) => {
//   const transporter = nodemailer.createTransport(config.emailConfig);

//   const verificationLink = `${config.frontendUrl}/verify-email?token=${token}`;

//   await transporter.sendMail({
//     from: config.emailFrom,
//     to: email,
//     subject: "Verify Your Email",
//     html: `
//       <h1>Email Verification</h1>
//       <p>Click the link below to verify your email:</p>
//       <a href="${verificationLink}">Verify Email</a>
//       <p>This link will expire in 1 hour.</p>
//     `,
//   });
// };

export interface CustomError extends Error {
  message: string;
  code?: string;
}
// Initialize Resend client
const resend = new Resend(config.resendApiKey);

// Function to send verification email
const sendVerificationEmail = async (email: string, token: string) => {
  const verificationLink = `${config.frontendUrl}/verify-email?token=${token}`;
  const emailContent = `
    <h1>Email Verification</h1>
    <p>Click the link below to verify your email:</p>
    <a href="${verificationLink}">Verify Email</a>
    <p>This link will expire in 1 hour.</p>
  `;

  try {
    await resend.emails.send({
      from: config.emailFrom,
      to: email,
      subject: "Verify Your Email",
      html: emailContent,
    });
    logger.info(`Verification email sent successfully to ${email}`);
  } catch (error) {
    const customError = error as CustomError;
    logger.error(
      `Failed to send verification email to ${email}: ${customError.message}`
    );
  }
};

// Function to send password reset email
const sendPasswordResetEmail = async (email: string, token: string) => {
  const resetLink = `${config.frontendUrl}/reset-password?token=${token}`;
  const emailContent = `
    <h1>Password Reset</h1>
    <p>Click the link below to reset your password:</p>
    <a href="${resetLink}">Reset Password</a>
    <p>This link will expire in 1 hour.</p>
  `;

  try {
    await resend.emails.send({
      from: config.emailFrom,
      to: email,
      subject: "Password Reset Request",
      html: emailContent,
    });
    logger.info(`Password reset email sent successfully to ${email}`);
  } catch (error) {
    const customError = error as CustomError;
    logger.error(
      `Failed to send password reset email to ${email}: ${customError.message}`
    );
  }
};

const isTokenBlacklisted = async (token: string) => {
  const blacklistedToken = await prisma.tokenBlacklist.findUnique({
    where: { token },
  });
  return !!blacklistedToken;
};

const authRoutes = new Elysia({ prefix: "/auth" })
  .post(
    "/register",
    async ({ body, set }) => {
      const { name, email, password } = body;

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        set.status = 409;
        return {
          message: "User with this email already exists",
          error: true,
        };
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Generate email verification token
      const emailVerifyToken = nanoid();
      const emailVerifyExpires = new Date(Date.now() + 3600000); // 1 hour

      try {
        const user = await prisma.user.create({
          data: {
            name,
            email,
            password: hashedPassword,
            emailVerifyToken,
            emailVerifyExpires,
          },
          select: {
            id: true,
            name: true,
            email: true,
          },
        });

        // Send verification email
        await sendVerificationEmail(email, emailVerifyToken);

        return {
          message:
            "User registered successfully. Please check your email to verify your account.",
          user,
        };
      } catch (error) {
        set.status = 500;
        return {
          message: "Registration failed",
          error: true,
        };
      }
    },
    {
      body: t.Object({
        name: t.String({
          minLength: 2,
          maxLength: 50,
        }),
        email: t.String({
          format: "email",
        }),
        password: t.String({
          minLength: 8,
          pattern:
            "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
        }),
      }),
    }
  )
  .post(
    "/verify-email",
    async ({ body, set }) => {
      const { token } = body;

      const user = await prisma.user.findFirst({
        where: {
          emailVerifyToken: token,
          emailVerifyExpires: { gt: new Date() },
        },
      });

      if (!user) {
        set.status = 400;
        return {
          message: "Invalid or expired verification token",
          error: true,
        };
      }

      await prisma.user.update({
        where: { id: user.id },
        data: {
          isEmailVerified: true,
          emailVerifyToken: null,
          emailVerifyExpires: null,
        },
      });

      return {
        message: "Email verified successfully",
      };
    },
    {
      body: t.Object({
        token: t.String(),
      }),
    }
  )
  .post(
    "/login",
    async ({ body, set }) => {
      const { email, password } = body;

      const user = await prisma.user.findUnique({
        where: { email },
      });

      // Rate limiting logic
      if (user) {
        const now = new Date();
        const tooManyAttempts =
          user.loginAttempts >= 5 &&
          user.lastLoginAttempt &&
          now.getTime() - user.lastLoginAttempt.getTime() < 15 * 60 * 1000; // 15 minutes

        if (tooManyAttempts) {
          set.status = 429;
          return {
            message: "Too many login attempts. Please try again later.",
            error: true,
          };
        }
      }

      if (!user) {
        set.status = 401;
        return {
          message: "Invalid email or password",
          error: true,
        };
      }

      // Check email verification
      if (!user.isEmailVerified) {
        set.status = 403;
        return {
          message: "Please verify your email before logging in",
          error: true,
        };
      }

      // Compare passwords
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        // Update login attempts
        await prisma.user.update({
          where: { id: user.id },
          data: {
            loginAttempts: { increment: 1 },
            lastLoginAttempt: new Date(),
          },
        });

        set.status = 401;
        return {
          message: "Invalid email or password",
          error: true,
        };
      }

      // Reset login attempts on successful login
      await prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: 0,
          lastLoginAttempt: null,
        },
      });

      // Generate tokens
      const accessToken = generateToken(
        { id: user.id, type: "access" },
        config.jwtSecret,
        "15m"
      );
      const refreshToken = generateToken(
        { id: user.id, type: "refresh" },
        config.refreshSecret,
        "7d"
      );

      // Store refresh token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          refreshToken,
          refreshTokenExpires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        },
      });

      return {
        message: "Login successful",
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      };
    },
    {
      body: t.Object({
        email: t.String({
          format: "email",
        }),
        password: t.String(),
      }),
    }
  )
  .post(
    "/forgot-password",
    async ({ body, set }) => {
      const { email } = body;

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        // Deliberate vague response for security
        return {
          message: "If an account exists, a password reset link has been sent",
        };
      }

      // Generate password reset token
      const passwordResetToken = nanoid();
      const passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour

      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordResetToken,
          passwordResetExpires,
        },
      });

      // Send password reset email
      await sendPasswordResetEmail(email, passwordResetToken);

      return {
        message: "Password reset link sent to your email",
      };
    },
    {
      body: t.Object({
        email: t.String({ format: "email" }),
      }),
    }
  )
  .post(
    "/reset-password",
    async ({ body, set }) => {
      const { token, newPassword } = body;

      const user = await prisma.user.findFirst({
        where: {
          passwordResetToken: token,
          passwordResetExpires: { gt: new Date() },
        },
      });

      if (!user) {
        set.status = 400;
        return {
          message: "Invalid or expired reset token",
          error: true,
        };
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and clear reset token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          passwordResetToken: null,
          passwordResetExpires: null,
        },
      });

      return {
        message: "Password reset successful",
      };
    },
    {
      body: t.Object({
        token: t.String(),
        newPassword: t.String({
          minLength: 8,
          pattern:
            "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
        }),
      }),
    }
  )
  .post(
    "/refresh-token",
    async ({ body, set }) => {
      const { refreshToken } = body;

      if (!refreshToken) {
        set.status = 401;
        return {
          message: "Refresh token is required",
          error: true,
        };
      }

      // Check if token is blacklisted
      if (await isTokenBlacklisted(refreshToken)) {
        set.status = 401;
        return {
          message: "Token has been invalidated",
          error: true,
        };
      }

      try {
        // Verify refresh token
        const decoded = jwt.verify(refreshToken, config.refreshSecret) as {
          id: string;
          type: string;
        };

        // Ensure it's a refresh token
        if (decoded.type !== "refresh") {
          set.status = 401;
          return {
            message: "Invalid token type",
            error: true,
          };
        }

        // Check user and token
        const user = await prisma.user.findUnique({
          where: {
            id: decoded.id,
            refreshToken: refreshToken,
            refreshTokenExpires: { gt: new Date() },
          },
          select: {
            id: true,
            email: true,
          },
        });

        if (!user) {
          set.status = 401;
          return {
            message: "Invalid refresh token",
            error: true,
          };
        }

        // Blacklist old refresh token
        await prisma.tokenBlacklist.create({
          data: {
            token: refreshToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          },
        });

        // Generate new tokens
        const newAccessToken = generateToken(
          { id: user.id, type: "access" },
          config.jwtSecret,
          "15m"
        );
        const newRefreshToken = generateToken(
          { id: user.id, type: "refresh" },
          config.refreshSecret,
          "7d"
        );

        // Update refresh token in database
        await prisma.user.update({
          where: { id: user.id },
          data: {
            refreshToken: newRefreshToken,
            refreshTokenExpires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          },
        });

        return {
          message: "Tokens refreshed successfully",
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        };
      } catch (error) {
        set.status = 401;
        return {
          message: "Invalid refresh token",
          error: true,
        };
      }
    },
    {
      body: t.Object({
        refreshToken: t.String(),
      }),
    }
  )
  .post(
    "/logout",
    async ({ body, set }) => {
      const { refreshToken } = body;

      if (!refreshToken) {
        set.status = 400;
        return {
          message: "Refresh token is required",
          error: true,
        };
      }

      try {
        // Blacklist the refresh token
        await prisma.tokenBlacklist.create({
          data: {
            token: refreshToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          },
        });

        // Clear refresh token from user
        await prisma.user.updateMany({
          where: { refreshToken },
          data: {
            refreshToken: null,
            refreshTokenExpires: null,
          },
        });

        return {
          message: "Logout successful",
        };
      } catch (error) {
        set.status = 401;
        return {
          message: "Logout failed",
          error: true,
        };
      }
    },
    {
      body: t.Object({
        refreshToken: t.String(),
      }),
    }
  );

export default authRoutes;
