import {setup, start} from 'applicationinsights';
import express, {ErrorRequestHandler} from 'express';
import cors from 'cors';
import nocache from 'nocache';
import {createLogger} from '@skyline/node-logger';
import {keyVaultConfigFn} from '@skyline/authenticated-proxy/config';

import {customAuthenticationApp} from './middleware';
import { contactSummaryStream } from './middleware/contactSummaryStream';

const app = express();

async function initializeApp() {
  const config = await keyVaultConfigFn();

  if (config.appinsightsInstrumentationkey) {
    setup(config.appinsightsInstrumentationkey);
    start();
  }

  const logger = createLogger(config.log);

  logger.debug(`Starting with configuration: ${config.toString()}`);

  const redis = {
    ...config.redis,
    sessionTtl: config.tenant.sessionTtl,
    refreshSessionTtl: config.tenant.refreshSessionTtl
  };

  // TODO: There will be two redis connections now; does that matter?
  const appConfig = {
    dataProviders: {
      ...config.dataProviders
    },
    pingFederate: {
      ...config.pingFederate,
      loginOptions: {
        client_id: config.pingFederate.clientId,
        pfidpadapterid: config.pingFederate.adapterId,
        redirect_uri: config.tenant.loginRedirectUrl,
        scope: config.pingFederate.scope,
        queryParams: config.pingFederate.loginUrlParams
      },
      logoutOptions: {
        post_logout_redirect_uri: config.tenant.logoutRedirectUrl,
        queryParams: config.pingFederate.logoutUrlParams
      },
      oauthOptions: {
        client_secret: config.pingFederate.clientSecret
      }
    },
    mimicUser: {
      enableMimicUser: config.tenant.enableMimicUser,
      mimicUserRoles: config.tenant.mimicUserRoles,
      mimicUserAuthorizationUrl: config.tenant.mimicUserAuthorizationUrl
    },
    enableProxyPassthrough: true,
    redis
  };

  const authenticationApp = customAuthenticationApp(appConfig, logger);
  const contactSummary=contactSummaryStream(appConfig,logger);

  app.disable('x-powered-by');
  app.use(nocache());

  if (config.cors.allowedOrigins.length > 0) {
    const corsOptions = {
      origin: config.cors.allowedOrigins,
      allowedHeaders: ['Session-Id', 'Content-Type'].concat(config.cors.allowedHeaders)
    };

    app.use(cors(corsOptions));
  }

  app.use((req, res, next) => {
    res.set('Content-Security-Policy', `script-src 'report-sample' 'self' 'unsafe-inline' 'unsafe-eval' assets.adobedtm.com *.lpsnmedia.net *.stripe.com *.azureedge.net cdn.gbqofs.com *.optum.com *.optumrx.com *.googleapis.com *.qualtrics.com *.healthsafe-id.com; style-src 'report-sample' 'self' 'unsafe-inline' *.azureedge.net *.googleapis.com; object-src 'none'; base-uri 'self'; worker-src blob:; manifest-src 'self';connect-src 'self' ${process.env.CONTENT_BASE_URL} wss: *.healthsafepay.com *.optumrx.com *.optum.com *.azure.com *.googleapis.com *.gstatic.com report.uhg.gbqofs.io siteintercept.qualtrics.com unitedhealthgroup.tt.omtrdc.net; data: *.optum.com *.healthsafepay.com fonts.gstatic.com content-hub.optumrx.com;`);
    res.set('Strict-Transport-Security', 'max-age= 31536000; includeSubDomains');
    next()
  })

  app.get('/', (req, res) => {
    res.end('Healthy!');
  });

  app.get('/apphealthcheck', (req, res) => {
    res.end("Healthy!")
  });

  app.use(config.routerPrefix, authenticationApp);
  app.use(config.routerPrefix,contactSummary);

  app.use((req, res) => {
    logger.warn(`URL not found. Request URL: ${req.url}`, req);
    res.status(404).end();
  });

  // Even though "next" isn't used, we need it to tell express
  // that this is our error handling middleware
  //
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use(function errorHandler(err: {statusCode?: number; message?: string; url?: string} | undefined, req, res, _) {
    logger.error(`Error processing request. Error: ${(err && err.message) || JSON.stringify(err)}`, err, req);
    res.status(500).end((config.nodeEnv === 'develop' && err && err.message) || undefined);
  } as ErrorRequestHandler);

  app.listen(config.port, () => logger.info(`Listening on port ${config.port}...`));
}

// Needed until top-level await is available in NodeJS
// eslint-disable-next-line @typescript-eslint/no-floating-promises
initializeApp();
