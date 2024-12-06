import { Elysia, t } from "elysia";
import bcrypt from "bcrypt";
import prisma from "../../utils/prisma";
import { generateToken } from "./utils/generateToken";
import getAuthConfig from "../../config/auth.config";
import crypto from "crypto";

const authConfig = getAuthConfig();

// Constants for security settings
const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  PASSWORD_SALT_ROUNDS: 12,
  PASSWORD_REGEX: {
    pattern: "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
    message:
      "Password must be at least 8 characters long and include a letter, number, and special character",
  },
  REFRESH_TOKEN_EXPIRES: 7 * 24 * 60 * 60 * 1000, // 7 days
  COOKIE_CONFIG: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite:
      process.env.NODE_ENV === "production"
        ? "strict"
        : ("lax" as "strict" | "lax"),
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
};

export const authRoute = new Elysia().group("/auth", (app) =>
  app
    .post(
      "/login",
      async ({ body, set, cookie }) => {
        const { email, password } = body;

        try {
          const user = await prisma.user.findUnique({
            where: { email },
          });

          // Enhanced rate limiting logic
          if (user) {
            const now = Date.now();
            const lastAttempt = user.lastLoginAttempt?.getTime() || 0;
            const calculateBackoffTime = (attempts: number) => {
              // Exponential backoff: Each failed attempt increases lockout duration
              return Math.min(
                SECURITY_CONFIG.LOCKOUT_DURATION * Math.pow(2, attempts - 1),
                60 * 60 * 1000 // Max 1 hour lockout
              );
            };
            const lockoutDuration = calculateBackoffTime(user.loginAttempts);
            const tooManyAttempts =
              user.loginAttempts >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS &&
              now - lastAttempt < lockoutDuration;

            if (tooManyAttempts) {
              set.status = 429;
              return {
                message: "Account temporarily locked. Please try again later.",
                error: true,
                remainingTime: lockoutDuration - (now - lastAttempt),
              };
            }
          }

          if (!user) {
            set.status = 401;
            return {
              message: "Invalid credentials",
              error: true,
            };
          }

          const isPasswordValid =
            user.password && (await bcrypt.compare(password, user.password));

          if (!isPasswordValid) {
            await prisma.user.update({
              where: { id: user.id },
              data: {
                loginAttempts: { increment: 1 },
                lastLoginAttempt: new Date(),
              },
            });

            set.status = 401;
            return {
              message: "Invalid credentials",
              error: true,
            };
          }

          // Reset login attempts and generate tokens
          const accessToken = generateToken(
            { id: user.id, type: "access" },
            authConfig.jwtSecret,
            authConfig.jwtExpiresIn
          );

          const refreshToken = generateToken(
            { id: user.id, type: "refresh" },
            authConfig.refreshSecret,
            "7d"
          );

          // Generate a token hash for storage
          const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

          await prisma.user.update({
            where: { id: user.id },
            data: {
              loginAttempts: 0,
              lastLoginAttempt: null,
              refreshToken: refreshTokenHash,
              refreshTokenExpires: new Date(
                Date.now() + SECURITY_CONFIG.REFRESH_TOKEN_EXPIRES
              ),
            },
          });

          // Set refresh token in HTTP-only cookie
          cookie.refreshToken.set({
            value: refreshToken,
            ...SECURITY_CONFIG.COOKIE_CONFIG,
          });

          return {
            message: "Login successful",
            accessToken,
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
            },
          };
        } catch (error) {
          console.error("Login error:", error);
          set.status = 500;
          return {
            message: "An error occurred during login",
            error: true,
            errorId: crypto.randomBytes(8).toString("hex"),
          };
        }
      },
      {
        body: t.Object({
          email: t.String({
            format: "email",
          }),
          password: t.String(),
        }),
        tags: ["Auth"],
        detail: {
          summary: "Login to the application",
          description: "Authenticate user and return JWT token",
        },
      }
    )
    .post(
      "/register",
      async ({ body, set }) => {
        const { name, email, password, username } = body;

        try {
          // Check for existing user - Alternative approach without transaction
          const [userByEmail, userByUsername] = await Promise.all([
            prisma.user.findUnique({
              where: { email },
            }),
            prisma.user.findUnique({
              where: { username },
            }),
          ]);

          if (userByEmail || userByUsername) {
            set.status = 409;
            return {
              message: userByEmail
                ? "Email already registered"
                : "Username already taken",
              error: true,
            };
          }

          // Enhanced password hashing
          const hashedPassword = await bcrypt.hash(
            password,
            SECURITY_CONFIG.PASSWORD_SALT_ROUNDS
          );

          const verificationToken = crypto.randomBytes(32).toString("hex");

          const user = await prisma.user.create({
            data: {
              name,
              email,
              password: hashedPassword,
              username,
              emailVerifyToken: verificationToken,
              emailVerifyExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            },
            select: {
              id: true,
              name: true,
              email: true,
              emailVerifyToken: true,
            },
          });

          // const user = await prisma.$transaction(async (tx) => {
          //   // Check existing users
          //   const existingEmail = await tx.user.findUnique({
          //     where: { email },
          //   });

          //   if (existingEmail) {
          //     throw new Error("Email already registered");
          //   }

          //   const existingUsername = await tx.user.findUnique({
          //     where: { username },
          //   });

          //   if (existingUsername) {
          //     throw new Error("Username already taken");
          //   }

          //   // Create new user
          //   return tx.user.create({
          //     data: {
          //       name,
          //       email,
          //       password: hashedPassword,
          //       username,
          //       emailVerifyToken: verificationToken,
          //       emailVerifyExpires: new Date(
          //         Date.now() + 24 * 60 * 60 * 1000
          //       ),
          //     },
          //     select: {
          //       id: true,
          //       name: true,
          //       email: true,
          //       emailVerifyToken: true,
          //     },
          //   });
          // });

          // TODO: Implement email verification service
          // await sendVerificationEmail(user.email, user.emailVerificationToken);

          return {
            message: "Registration successful. Please verify your email.",
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
            },
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
            pattern: SECURITY_CONFIG.PASSWORD_REGEX.pattern,
          }),
          username: t.String({
            minLength: 2,
            maxLength: 50,
          }),
        }),
        tags: ["Auth"],
        detail: {
          summary: "Register to the application",
          description: "Register user with email verification",
        },
      }
    )
);
