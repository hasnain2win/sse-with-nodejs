import express, { Request, Response, NextFunction } from "express";
import { getSessionManagerSingleton } from "@skyline/oauth-proxy-common";
import { Logger, createLogger } from "@skyline/node-logger";
import { AuthenticationAppParams } from "@skyline/authenticated-proxy";
import { ErrorRequestHandler } from "express";

const nodeEnv = process.env.NODE_ENV;
const router = express.Router();

export function contactSummaryStream(
  appConfig: AuthenticationAppParams,
  logger: Logger = createLogger()
) {
  logger.info("Started contactSummaryStream function");

  const config = {
    ...appConfig,
    redis: {
      ...appConfig.redis,
      refreshSessionTtl: appConfig.redis.refreshSessionTtl || 0,
    },
  };

  const sessionManager = getSessionManagerSingleton(config.redis, logger);

  router.get("/contactSummaryStream/channelName", async (req, res) => {
    logger.info("contactSummaryStream API called");
    const channel = req.query.channelName;

    if (typeof channel !== "string") {
      logger.error("Invalid channel parameter");
      res.status(400).json({
        errorCode: 400,
        message: "channelName parameter is mandatory",
        timeStamp: new Date().toISOString(),
        endpoint: req.originalUrl,
      });
      return;
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const redisClient = sessionManager.redisClient.duplicate();
    logger.info(`Redis client created for stream: ${channel}`);

    let lastId = '0'; // Start from the beginning of the stream
    const channelName = channel;

    logger.info("Channel name: " + channelName);

    const readStreamMessages = async () => {
      try {
        logger.info(`Attempting to read from Redis stream: ${channelName} with lastId: ${lastId}`);

        // Send the XREAD command to fetch a single message
        const result: [string, [[string, [string, string][]]]][] = await new Promise((resolve, reject) => {
          redisClient.send_command('XREAD', ['BLOCK', '0', 'STREAMS', channelName, lastId], (err, result) => {
            if (err) {
              reject(err);
            } else {
              resolve(result);
            }
          });
        });

        if (result) {
          logger.info(`Result received from Redis stream: ${JSON.stringify(result)}`);
          const messages = result[0][1]; // [streamName, [messages]]

          // Assuming you only need the first message
          const message = messages[0];
          lastId = message[0]; // The ID of the message
          const messageData = message[1][1]; // Assuming the message data is at index 1 in the array

          logger.info(`Data received from Redis stream: ${messageData}`);
         
          res.write(`data: ${String(messageData)}\n\n`);

          // Close the Redis connection and SSE connection after sending the first message
          await redisClient.quit();
          logger.info(`Redis client disconnected for stream: ${channelName}`);
          res.end();
        } else {
          logger.info(`No new messages in Redis stream: ${channelName}`);
        }
      } catch (err) {
        logger.error(`Error reading from Redis stream: ${channelName}. Error: ${err}`);
        res.write(`event: error\ndata: ${JSON.stringify({ errorCode: 500, message: `Error reading from Redis stream: ${err}` })}\n\n`);
      }
    };

    // Start reading from the stream (this will close the connection after the first message)
    readStreamMessages().catch((err) => {
      logger.error(`Unhandled error in readStreamMessages: ${err}`);
      res.status(500).json({
        errorCode: 500,
        message: `Unhandled error in readStreamMessages: ${err}`,
      });
    });

    req.on("close", () => {
      redisClient.quit();
      logger.info(`Redis client disconnected for stream: ${channelName}`);
      res.end();
    });
  });

  const errorHandler: ErrorRequestHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
    if (err && err.statusCode) {
      logger.error(`Error response from ${req.url}: ${err.message || JSON.stringify(err)}`, err, req);
      res.status(err.statusCode).end((nodeEnv === "develop" && err.message) || undefined);
    } else {
      next(err);
    }
  };

  router.use(errorHandler);

  logger.info("End of contactSummaryStream");
  return router;
}
