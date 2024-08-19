import express from 'express';
import { getSessionManagerSingleton } from '@skyline/oauth-proxy-common';
import { Logger, createLogger } from '@skyline/node-logger';
import { AuthenticationAppParams } from '@skyline/authenticated-proxy';

const router = express.Router();

export function contactSummaryStream(appConfig: AuthenticationAppParams, logger: Logger = createLogger()) {
  const config = { ...appConfig, redis: { ...appConfig.redis, refreshSessionTtl: appConfig.redis.refreshSessionTtl || 0 } };
  const sessionManager = getSessionManagerSingleton(config.redis, logger);

  router.get('/contactSummaryStream/', async (req, res) => {
    logger.info('contactSummaryStream api called');
    const channel = req.query.channel;

    if (typeof channel !== 'string') {
      logger.error('Invalid channel parameter');
      res.status(400).send('Invalid channel parameter');
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    try {
      await sessionManager.redisClient.subscribe(channel, (message) => {
        if (message) {
          const data = message.toString();
          logger.info(`Data received from Redis: ${data}`);
          logger.info(`Channel name: ${channel}`);
          res.write(`data: ${data}\n\n`);
        } else {
          logger.warn('Received null message from Redis');
        }
      });

      req.on('close', async () => {
        try {
          await sessionManager.redisClient.unsubscribe(channel);
          logger.info('Client has disconnected connection');
          res.end();
        } catch (err) {
          logger.error('Error unsubscribing from Redis channel: ', err);
          res.status(500).end();
        }
      });
    } catch (err) {
      logger.error('Error subscribing to Redis channel: ', err);
      res.status(500).send('Error subscribing to Redis channel');
    }
  });

  return router;
}
