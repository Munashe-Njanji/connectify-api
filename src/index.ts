import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { config } from "./config";
import fs from "fs";
import path from "path";
import pino from "pino";
import { v4 as uuidv4 } from "uuid";
import { CustomError } from "./routes/auth";

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, "../logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Configure Pino logger with multiple targets
export const logger = pino({
  level: config.logLevel || "info",
  transport: {
    targets: [
      {
        target: "pino-pretty",
        level: "info",
        options: {
          colorize: true,
          translateTime: "SYS:standard",
        },
      },
      {
        target: "pino/file",
        level: "info",
        options: {
          destination: path.join(
            logsDir,
            `app-${new Date().toISOString().split("T")[0]}.log`
          ),
          sync: false,
        },
      },
    ],
  },
});

// Function to find an available port
async function findAvailablePort(
  startPort: number,
  maxPort: number
): Promise<number> {
  for (let port = startPort; port <= maxPort; port++) {
    try {
      const server = Bun.serve({
        port,
        fetch: () => new Response("test"),
      });
      server.stop(); // Stop the temporary server if successful
      return port;
    } catch (err) {
      logger.warn(`Port ${port} is in use, trying next port`);
      continue;
    }
  }
  throw new Error(
    `No available ports found between ${startPort} and ${maxPort}`
  );
}

// Middleware for request logging
const loggerMiddleware = (app: Elysia) =>
  app.derive(({ request }) => {
    const requestId = uuidv4();
    const startTime = performance.now();

    return {
      requestId,
      logger: logger.child({ requestId }),
      getRequestDuration: () =>
        `${(performance.now() - startTime).toFixed(2)}ms`,
    };
  });

// Error handler middleware
const errorHandler = (app: Elysia) =>
  app.onError(({ code, error, set }) => {
    logger.error({ code, error }, "An error occurred");

    set.status = code === "NOT_FOUND" ? 404 : 500;
    return {
      success: false,
      error: error.message,
      code,
    };
  });

// Create the main app with middleware
const app = new Elysia()
  .use(cors())
  .use(swagger())
  .use(loggerMiddleware)
  .use(errorHandler);

// Add request logging
app.derive(({ logger, request, requestId, getRequestDuration }) => {
  logger.info(
    {
      method: request.method,
      url: request.url,
      requestId,
    },
    "Incoming request"
  );

  return {
    beforeHandle: () => {
      logger.info({ requestId }, "Processing request");
    },
    afterHandle: () => {
      logger.info(
        {
          requestId,
          duration: getRequestDuration(),
        },
        "Request completed"
      );
    },
  };
});

// Dynamically load routes
const routesDir = path.join(__dirname, "routes");

fs.readdirSync(routesDir)
  .filter(
    (file) =>
      file.endsWith(".ts") &&
      !file.includes(".test.") &&
      !file.includes(".spec.")
  )
  .forEach((file) => {
    const routePath = path.join(routesDir, file);
    logger.info({ routePath }, "Loading route");

    try {
      const route = require(routePath).default;

      if (route && typeof route.use === "function") {
        app.use(route);
        logger.info({ routePath }, "Route loaded successfully");
      } else {
        logger.warn({ routePath }, "Invalid route module");
      }
    } catch (error) {
      logger.error({ routePath, error }, "Failed to load route");
    }
  });

// Graceful shutdown handler
const shutdown = async () => {
  logger.info("Shutting down server...");
  process.exit(0);
};

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// Retry logic for starting the server
const startServer = async (startPort: number, maxPort: number) => {
  try {
    // Find an available port
    const port = await findAvailablePort(startPort, maxPort);

    // Start the server on the available port
    await app.listen(port);
    logger.info({ port }, `🚀 Server running at http://localhost:${port}`);

    // Keep the process alive
    process.stdin.resume();

    logger.info("Server is ready to handle requests");
  } catch (error) {
    const customError = error as CustomError;
    if (customError.code === "EADDRINUSE") {
      logger.warn(
        `Port ${startPort} is in use. Retrying on the next available port...`
      );

      // Retry server startup on the next port
      if (startPort < maxPort) {
        return startServer(startPort + 1, maxPort);
      } else {
        logger.error(
          `All ports between ${startPort} and ${maxPort} are in use.`
        );
      }
    } else {
      logger.error(error, "Failed to start server");
    }
    process.exit(1);
  }
};

// Start the application
(async () => {
  const startPort = Number(config.port) || 4000;
  const maxPort = startPort + 10;

  await startServer(startPort, maxPort);
})();

export default app;
