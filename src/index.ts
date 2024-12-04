import cors from "@elysiajs/cors";
import Elysia from "elysia";
import { errorMiddleware } from "./core/middlewares/error.middleware";
import swagger from "@elysiajs/swagger";
import { appConfig } from "./config/app.config";
import { authRoute } from "./modules/auth/routes";
import userRoutes from "./modules/user/routes";
import postsRoute from "./modules/content/posts/routes";
import commentsRoutes from "./modules/content/comments/routes";

const app = new Elysia()
  .use(cors())
  .use(errorMiddleware)

  .use(
    swagger({
      documentation: {
        info: {
          title: "LinkedIn Clone API Documentation",
          description: `
A comprehensive API for a LinkedIn clone application.
          
## Features
- Authentication & Authorization
- User Profile Management
- Posts & Content Management
- Comments & Interactions
- Network Connections
          
## Getting Started
To use this API, you'll need to authenticate first using the /auth endpoints.
          `,
          version: "1.0.0",
          contact: {
            name: "Munashe Njanji",
            email: "munashenjanji45@gmail.com",
            url: "https://github.com/Munashe-Njanji",
          },
          license: {
            name: "MIT",
            url: "https://opensource.org/licenses/MIT",
          },
        },
        tags: [
          {
            name: "Auth",
            description: "Authentication and authorization endpoints",
          },
          { name: "Users", description: "User profile management endpoints" },
          {
            name: "Posts",
            description: "Post creation and management endpoints",
          },
          { name: "Comments", description: "Comment management endpoints" },
          {
            name: "Connections",
            description: "Network connection management endpoints",
          },
          { name: "Search", description: "Search functionality endpoints" },
        ],
        servers: [
          {
            url: "http://localhost:4000",
            description: "Development server",
          },
          {
            url: "https://api.yourproduction.com",
            description: "Production server",
          },
        ],
      },
      path: "/swagger",
    })
  )

  .group(appConfig.apiPrefix, (app) =>
    app.use(authRoute).use(userRoutes).use(postsRoute).use(commentsRoutes)
  )

  .listen(appConfig.port, () => {
    console.log(`🚀 Server running at ${appConfig.url}:${appConfig.port}`);
    console.log(
      `📚 Swagger documentation available at ${appConfig.url}:${appConfig.port}/swagger`
    );
  });
