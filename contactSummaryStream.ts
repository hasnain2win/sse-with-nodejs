import express, { ErrorRequestHandler } from "express";
import { getSessionManagerSingleton } from "@skyline/oauth-proxy-common";
import { Logger, createLogger } from "@skyline/node-logger";
import { AuthenticationAppParams } from "@skyline/authenticated-proxy";

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
    logger.info(`Redis client created for channel: ${channel}`);

    try {
      await redisClient.subscribe(channel);
      logger.info(`Subscribed to channel: ${channel}`);

      const messageHandler = (receivedChannel: string, message: string) => {
        if (receivedChannel === channel) {
          logger.info(`Data received from Redis: ${message}`);
          res.write(`data: ${message}\n\n`);
        }
      };

      redisClient.on("message", messageHandler);

      req.on("close", async () => {
        redisClient.removeListener("message", messageHandler);
        try {
          await redisClient.unsubscribe(channel);
          logger.info(
            `Client disconnected or unsubscribed from channel: ${channel}`
          );
        } catch (err) {
          logger.error(
            `Error unsubscribing from Redis channel: ${channel}. Error: ${err}`
          );
        } finally {
          await redisClient.quit();
          logger.info(`Redis client disconnected for channel: ${channel}`);
          res.end();
        }
      });
    } catch (err) {
      logger.error(
        `Error subscribing to Redis channel: ${channel}. Error: ${err}`
      );
      res.status(500).json({
        errorCode: 500,
        message: `Error subscribing to Redis channel : ${err}`,
      });
    }
  });

  const errorHandler: ErrorRequestHandler = (
    err: { statusCode?: number; message?: string; url?: string } | undefined,
    req,
    res,
    next
  ) => {
    if (err && err.statusCode) {
      logger.error(
        `Error response from ${req.url}: ${err.message || JSON.stringify(err)}`,
        err,
        req
      );
      res
        .status(err.statusCode)
        .end((nodeEnv === "develop" && err.message) || undefined);
    } else {
      next(err);
    }
  };

  router.use(errorHandler);

  logger.info("End of contactSummaryStream");
  return router;
}
