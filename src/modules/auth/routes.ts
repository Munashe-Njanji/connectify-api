import { Elysia, t } from "elysia";
import bcrypt from "bcrypt";
import prisma from "../../utils/prisma";

export const authRoute = new Elysia().group("/auth", (app) =>
  app
    .get(
      "/login",
      () => {
        return { message: "Login route" };
      },
      {
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
        const { name, email, password, username } = body as {
          name: string;
          email: string;
          password: string;
          username: string;
        };

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
        try {
          const user = await prisma.user.create({
            data: {
              name,
              email,
              password: hashedPassword,
              username,
            },
            select: {
              id: true,
              name: true,
              email: true,
            },
          });

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
        tags: ["Auth"],
        detail: {
          summary: "Register to the application",
          description: "Register user.",
        },
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
          username: t.String({
            minLength: 2,
            maxLength: 50,
          }),
        }),
      }
    )
);
