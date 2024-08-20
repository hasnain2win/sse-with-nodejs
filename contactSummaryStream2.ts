import express from 'express';
import { getSessionManagerSingleton } from '@skyline/oauth-proxy-common';
import { Logger, createLogger } from '@skyline/node-logger';
import { AuthenticationAppParams } from '@skyline/authenticated-proxy';
 
const router = express.Router();
 
export function contactSummaryStream(appConfig: AuthenticationAppParams, logger: Logger = createLogger()) {
  logger.info('Started contactSummaryStream: function')
  const config = { ...appConfig, redis: { ...appConfig.redis, refreshSessionTtl: appConfig.redis.refreshSessionTtl || 0 } };
  const sessionManager = getSessionManagerSingleton(config.redis, logger);

  router.get('/contactSummaryStream/channelName/', async (req, res) => {
    logger.info('contactSummaryStream API called');
    const channel = req.query.channel;
    if (typeof channel !== 'string') {
      logger.error('Invalid channel parameter');
      return res.status(400).send('Invalid channel parameter');
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    sessionManager.redisClient.subscribe(channel);
    logger.info(`subscribed for channel: ${channel}`)
    sessionManager.redisClient.on('message', (receivedChannel, message) => {
      if (receivedChannel === channel) {
        logger.info(`Data received from Redis: ${message}`);
        res.write(`data: ${message}\n\n`);
      }
    });

    req.on('close', async () => {
      try {
        await sessionManager.redisClient.unsubscribe(channel);
        logger.info(`Client has disconnected or unsubscribed connection for channel: ${channel}`);
        res.end();
      } catch (err) {
        logger.error(`Error unsubscribing from Redis channel: ${channel}  with Error : ${err}`);
        res.status(500).end();
      }
    });
  });
  logger.info('End of contactSummaryStream');
  return router;
}
