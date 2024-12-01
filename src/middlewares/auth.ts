import { Elysia } from "elysia";
import { JWTPayload, jwtVerify } from "jose";
import { UserPayload } from "../types";
import prisma from "../utils/prisma";

export const authenticate = new Elysia()
  .derive(async ({ request, set }) => {
    try {
      const authHeader = request.headers.get("Authorization");
      
      if (!authHeader?.startsWith("Bearer ")) {
        set.status = 401;
        throw new Error("Authorization header missing or invalid");
      }

      const token = authHeader.split(" ")[1];
      if (!token) {
        set.status = 401;
        throw new Error("Token missing");
      }

      // Replace with your actual JWT secret
      const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secret-key');
      const { payload } = await jwtVerify(token, secret);

      if (!payload.sub) {
        set.status = 401;
        throw new Error("Invalid token payload");
      }

      // Fetch user from database to ensure they exist
      const user = await prisma.user.findUnique({
        where: { id: payload.sub },
        select: { id: true, name: true, email: true }
      });

      if (!user) {
        set.status = 401;
        throw new Error("User not found");
      }

      return { user };
    } catch (error) {
      set.status = 401;
      throw new Error("Authentication failed");
    }
  });