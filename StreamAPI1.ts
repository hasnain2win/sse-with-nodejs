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
    logger.info(`Redis client created for stream: ${channel}`);

    let lastId = '0';
    const channelName = channel;
    logger.info("channl name"+channelName)

    const readStreamMessages = async () => {
      while (true) {
        try {
          logger.info(`Attempting to read from Redis stream: ${channelName} with lastId: ${lastId}`);
          redisClient.send_command('XREAD', ['BLOCK', '0', 'STREAMS', channelName, lastId], (err, result) => {
            if (err) {
              logger.error(`Error reading from Redis stream: ${channelName}. Error: ${err}`);
              res.status(500).json({
                errorCode: 500,
                message: `Error reading from Redis stream: ${err}`,
              });
              return;
            }

            if (result) {
              logger.info(`Result received from Redis stream: ${JSON.stringify(result)}`);
              const messages = result[0][1];
              messages.forEach((message: [string, any[]]) => {
                lastId = message[0];
                const messageData = message[1][1];

                logger.info(`Data received from Redis stream: ${messageData}`);
                res.write(`data: ${messageData}\n\n`);
              });
            } else {
              logger.info(`No new messages in Redis stream: ${channelName}`);
            }
          });
        } catch (err) {
          logger.error(`Error reading from Redis stream: ${channelName}. Error: ${err}`);
          res.status(500).json({
            errorCode: 500,
            message: `Error reading from Redis stream: ${err}`,
          });
          break;
        }
      }
    };

    readStreamMessages();

    req.on("close", async () => {
      try {
        await redisClient.quit();
        logger.info(`Redis client disconnected for stream: ${channelName}`);
        res.end();
      } catch (err) {
        logger.error(`Error closing Redis connection for stream: ${channelName}. Error: ${err}`);
      }
    });
  });

  const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
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
