/* eslint @skyline/optum/no-long-files: 0 */
import express, {ErrorRequestHandler} from 'express';
import {
  getUnauthorizedError,
  getBadRequestError,
  getSessionIdFromRequest,
  getSessionManagerSingleton,
  SessionObject
} from '@skyline/oauth-proxy-common';
import {Logger, createLogger} from '@skyline/node-logger';
import {AuthenticationAppParams} from '@skyline/authenticated-proxy';
import {getLoginUrl} from '@skyline/authenticated-proxy/middleware/handlers/login';
import {logout} from '@skyline/authenticated-proxy/middleware/handlers/logout';
import {
  upgradeSession,
  createSessionFromRefreshToken
} from '@skyline/authenticated-proxy/middleware/handlers/createSession';
import {refreshSession} from '@skyline/authenticated-proxy/middleware/handlers/refreshSession';
import {
  encryptSecret,
  decryptSecret
} from '@skyline/authenticated-proxy/middleware/handlers/secureProxy/manageSecureSession';
import {createProxy} from 'http-proxy';

import {createSession, getPermissions, PingFederateConfig, maskString} from './handlers/createSession';
import {secureProxy} from './handlers/secureProxy';
import { getAuthPassPspToken } from './authpass-service';

const nodeEnv = process.env.NODE_ENV;
const router = express.Router();

export {getSessionIdFromRequest};

export function customAuthenticationApp(appConfig: AuthenticationAppParams, logger: Logger = createLogger()) {
  const config = {...appConfig, redis: {...appConfig.redis, refreshSessionTtl: appConfig.redis.refreshSessionTtl || 0}};
  const sessionManager = getSessionManagerSingleton(config.redis, logger);
  
  const proxy = createProxy();

  router.get('/login', (req, res) => {
    logger.info("In AuthProxy Pingfederate Login");
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const {c: client} = req.query;
    const {loginOptions, loginUrl} = config.pingFederate;

    let pingFederateLoginUrl = loginUrl;
    let pingFederateLoginOptions = loginOptions;
    
    if (client) {
      pingFederateLoginUrl = process.env.EXTERNAL_PF_LOGIN_URL ?? '';
      pingFederateLoginOptions = {
        client_id: process.env.EXTERNAL_PF_CLIENT_ID ?? '',
        pfidpadapterid: process.env.EXTERNAL_PF_ADAPTER_ID ?? '',
        redirect_uri: process.env.EXTERNAL_PF_REDIRECT_URI ? `${process.env.EXTERNAL_PF_REDIRECT_URI}${String(client)}` : '',
        scope: process.env.EXTERNAL_PF_SCOPE ?? '',
        queryParams: [{
            "key": "acr_values",
            "value": process.env.EXTERNAL_PF_ACR_VALUES ?? ''  
        }]
      }
    }

    res.redirect(getLoginUrl(pingFederateLoginUrl, pingFederateLoginOptions, {}));
  });

  router.post('/session/encrypt', express.json(), async (req, res, next) => {
    try {
      const sessionId = getSessionIdFromRequest(req);
      if (!sessionId) {
        throw getUnauthorizedError('Session ID not found in headers');
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {secret} = req.body;
      if (!secret && typeof secret !== 'object') {
        throw getBadRequestError('please provide secret in the body');
      }

      const encryptedSecret = await encryptSecret(sessionId, secret, sessionManager, logger);

      res.send({secret: encryptedSecret});
    } catch (e) {
      next(e);
    }
  });

  router.post('/session/decrypt', express.json(), async (req, res, next) => {
    try {
      const sessionId = getSessionIdFromRequest(req);
      if (!sessionId) {
        throw getUnauthorizedError('Session ID not found in headers');
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {secret} = req.body;
      if (!secret && typeof secret !== 'string') {
        throw getBadRequestError('please provide secret in the body');
      }
      const decryptedSecret = await decryptSecret(sessionId, secret, sessionManager, logger);

      res.send({secret: decryptedSecret});
    } catch (e) {
      next(e);
    }
  });

  router.put('/session', express.json(), async (req, res, next) => {
    try {
      const {pingFederate, redis, dataProviders} = config;
      // eslint-disable-next-line camelcase, @typescript-eslint/no-unsafe-assignment
      const {code, sessionId, additional_info} = req.body;
      // eslint-disable-next-line camelcase, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
      const redirect_uri = pingFederate.loginOptions.redirect_uri || req.query.redirect_uri;

      const pingFederateConfig = {
        tokenUrl: pingFederate.tokenUrl,
        oauthOptions: {
          ...pingFederate.oauthOptions,
          client_id: pingFederate.loginOptions.client_id,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          redirect_uri
        }
      };

      const authenticatedSessionId = await upgradeSession(
        code,
        sessionId,
        redis.sessionTtl,
        pingFederateConfig as PingFederateConfig,
        dataProviders,
        sessionManager,
        additional_info
      );

      res.json(authenticatedSessionId);
    } catch (e) {
      next(e);
    }
  });

  router.post('/session', express.urlencoded({extended: true}), async (req, res, next) => {
    try {
      logger.info(`${req.body?.code || ''} ----------- In AuthProxy Create User Session ----------`);
      const startTime = Date.now();
      const {pingFederate, redis, dataProviders} = config;
      // eslint-disable-next-line camelcase
      const {code, profile, additional_info, generateRefreshToken, refreshToken, checkForExistingSession, externalClientId} = req.body as {
        code?: string;
        profile?: string;
        generateRefreshToken?: boolean;
        externalClientId?: string;
        refreshToken?: string;
        // eslint-disable-next-line camelcase
        additional_info?: {[key: string]: any};
        checkForExistingSession?: 'true';
      };
      // eslint-disable-next-line camelcase, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
      const pingFederateConfig = !externalClientId ? {
        tokenUrl: pingFederate.tokenUrl,
        oauthOptions: {
          ...pingFederate.oauthOptions,
          client_id: pingFederate.loginOptions.client_id,
          redirect_uri: pingFederate.loginOptions.redirect_uri
        },
        jwksUrl: process.env.IAM_JWKS_URI
      } : {
        tokenUrl: process.env.EXTERNAL_PF_TOKEN_URL,
        oauthOptions: {
          client_id: process.env.EXTERNAL_PF_CLIENT_ID,
          client_secret: process.env.EXTERNAL_PF_CLIENT_SECRET,
          redirect_uri: `${process.env.EXTERNAL_PF_REDIRECT_URI}${externalClientId}`
        },
        jwksUrl: process.env.EXTERNAL_IAM_JWKS_URI
      };

      let sessionResponse: any;

      if (code !== undefined) {
        sessionResponse = await createSession(
          code,
          !!generateRefreshToken,
          redis.sessionTtl,
          redis.refreshSessionTtl,
          pingFederateConfig as PingFederateConfig,
          dataProviders,
          sessionManager,
          logger,
          profile,
          additional_info,
          checkForExistingSession === 'true',
          externalClientId
        );
      } else if (refreshToken) {
        sessionResponse = await createSessionFromRefreshToken(
          refreshToken,
          redis.sessionTtl,
          pingFederateConfig as PingFederateConfig,
          dataProviders,
          sessionManager,
          logger
        );
      } else {
        throw getBadRequestError('Must specify either code or refresh token');
      }
      logger.info(`${code} ----------- Created User Session ${maskString(sessionResponse?.sessionId)} in : ${Date.now() - startTime} msecs: ${sessionResponse.msid} ----------`);
      res.json(sessionResponse);
    } catch (e) {
      next(e);
    }
  });

  router.post('/active', express.json(), async (req, res, next) => {
    const {redis} = config;
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {sessionId} = req.body;

      if (!sessionId) {
        throw getUnauthorizedError('No session given');
      }

      const sessionInfo = await sessionManager.asyncGet(sessionId as string);

      if (sessionInfo === null) {
        // No Session - Session Timeout
        logger.info(`${maskString(sessionId)} - No Session`);
        res.json({message: 'call success', isActive: false, reLogin: true});
      } else {
        const sessionObj: SessionObject & {isAuthenticated: boolean} = JSON.parse(sessionInfo);
        if (!sessionObj.isAuthenticated) {
          // Session Inactive - Session Timeout
          logger.info(`${maskString(sessionId)} - Session Inactive`);
          res.json({message: 'call success', isActive: false, reLogin: true});
        } else {
          const activeSession = await sessionManager.asyncGet(`session-${sessionObj?.userInfo?.MSID}`);
  
          if (activeSession !== null) {
            if (activeSession === maskString(sessionId)) {
              await sessionManager.redisClient.expire(`session-${sessionObj?.userInfo?.MSID}`, redis.sessionTtl);
              res.json({message: 'call success', isActive: true});
            } else {
              await sessionManager.clearSession(sessionId);
              // Session Inactive - New Session Created
              logger.info(`${maskString(sessionId)} - Clearing Previous Session`);
              res.json({message: 'call success', isActive: false, reLogin: false});
            }
          } else {
            logger.info(`${maskString(sessionId)} - Session switch success Redis`);
            await sessionManager.redisClient.set(`session-${sessionObj?.userInfo?.MSID}`, maskString(sessionId));
            await sessionManager.redisClient.expire(`session-${sessionObj?.userInfo?.MSID}`, redis.sessionTtl);
            res.json({message: 'call success', isActive: true});
          }
        }
      }
       
    } catch (e) {
      logger.error('Redis connection Error: ', e);
      next(e);
    }
  });

  // TODO: Refactor using JWT to verify that user has the requested profile
  router.post('/getPermissions', express.json(), async (req, res, next) => {
    try {
      const {profile} = req.body as { profile?: string; };
      const envFlag = process.env.ENV_FLAG;
      const profileKey = `${envFlag}${profile}`;
      const permissionsResponse = await getPermissions(profileKey, sessionManager, logger);

      if (permissionsResponse.length >= 1) {
        res.json(permissionsResponse);
      } else {
        next({statusCode: 404});
      }

    } catch (e) {
      next(e);
    }
  });

  // TODO: Refactor as "/getCachedPermissions"
  router.post('/getRoles', express.json(), async (req, res, next) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {profile} = req.body;

      if (!profile) {
        throw getUnauthorizedError('Profile is null');
      }

      const roles = await sessionManager.asyncGet(profile);
      const rolesInfo: string[] = roles ? JSON.parse(roles) : [];

      res.json({roles: rolesInfo});
       
    } catch (e) {
      logger.error('Redis connection Error: ', e);
      next(e);
    }
  });

  // TODO: Refactor as "/setCachedPermissions"
  router.post('/setRoles', express.json(), async (req, res, next) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {profile, roles} = req.body;
      const {msid, token} = req.headers;

      if (!profile || !roles) {
        throw getUnauthorizedError('Profile or roles are null');
      }

      const authorizedRoleSetters = ['kshashid', 'ssengu10', 'hpatel81', 'csahansr'];
      if (!authorizedRoleSetters.some((authorizedMsid) => authorizedMsid === msid)) {
        throw getUnauthorizedError('Unauthorized');
      }

      const sessionInfo = await sessionManager.asyncGet(token as string);

      if(sessionInfo !== null) {
        const sessionObj: SessionObject & {isAuthenticated: boolean} = JSON.parse(sessionInfo);
        if (!sessionObj.isAuthenticated) {
          throw getUnauthorizedError('Unauthorized');
        }
        if(sessionObj?.userInfo?.MSID !== msid) {
          throw getUnauthorizedError('Unauthorized');
        }

        await sessionManager.redisClient.set(profile, JSON.stringify(roles));
        res.json({message: 'Success'});
      }
       
    } catch (e) {
      logger.error('Redis connection Error: ', e);
      next(e);
    }
  });

  // TODO: test and build test case
  router.post('/logout', express.json(), async (req, res, next) => {
    try {
      const {pingFederate} = config;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {sessionId} = req.body;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const {query} = req;

      if (!sessionId) {
        throw getUnauthorizedError('No session given');
      }
      logger.info(`${maskString(sessionId)} - Logout Triggered`);
      const session = await sessionManager.getSession(sessionId);
      if(session !== null) {
        const msid = session?.userInfo?.MSID;
        const activeSession = await sessionManager.asyncGet(`session-${msid}`);
        const finalLogoutUrl = await logout(
          sessionId,
          config.redis.sessionTtl,
          pingFederate.logoutUrl,
          pingFederate.logoutOptions,
          sessionManager,
          query as any
        );
        if (activeSession === maskString(sessionId)) {
          sessionManager.asyncDel(`session-${msid}`);
        }
        logger.info(`${maskString(sessionId)} - Logged Out`);
        // returning the logoutUrl in the JSON response for OneHealthcareId (OptumId Cloud)
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        if (query.disableRedirect === 'true' || query.ohid === 'true') {
          res.json({message: 'logout success', logoutUrl: finalLogoutUrl});
        } else {
          res.redirect(finalLogoutUrl);
        }
      }
    } catch (e) {
      logger.error('logout error: ', e);
      next(e);
    }
  });

  if (config.enableProxyPassthrough) {
    router.use('/secure/:providerName', async (req, res, next) => {
      try {
        const sessionId = getSessionIdFromRequest(req);
        const {providerName} = req.params;

        if (!sessionId) {
          throw getUnauthorizedError('Session ID not found in headers');
        }
        const {pingFederate, redis, dataProviders} = config;
        const currentProvider = dataProviders[providerName];
        if (!currentProvider) {
          throw getUnauthorizedError('Provider not found');
        }

        const pfConfig = {
          tokenUrl: pingFederate.tokenUrl,
          oauthOptions: {
            ...pingFederate.oauthOptions,
            client_id: pingFederate.loginOptions.client_id,
            redirect_uri: pingFederate.loginOptions.redirect_uri
          },
          refreshTokenTtl: redis.refreshSessionTtl
        };

        await secureProxy(
          sessionId,
          redis.sessionTtl,
          pfConfig,
          providerName,
          currentProvider,
          sessionManager,
          req,
          res,
          next,
          proxy,
          logger
        );


      } catch (e) {
        next(e);
      }
    });
  }

  router.put('/refresh', async (req, res, next) => {
    try {
      const {redis} = config;
      const sessionId = getSessionIdFromRequest(req);

      if (!sessionId) {
        throw getUnauthorizedError('Session ID not found in headers');
      }

      const sessionUpdated = await refreshSession(sessionId, redis.sessionTtl, sessionManager);

      res.json(sessionUpdated);
    } catch (e) {
      next(e);
    }
  });

  router.post('/getAccessToken', express.json(), async (req, res, next) => {
    try{
      logger.info("----------- In AuthProxy Get Access Token ----------");
      const {sessionId} = req.body;

      if (!sessionId) {
        throw getBadRequestError('Session ID not found in headers');
      }

      const session = await sessionManager.getSession(sessionId);

      if(session !== null){
        const pf_access_token = session?.pf_access_token;
        logger.info("Fetched PF Access Token successfully");
        res.json({token: pf_access_token});
      } else {
        throw getUnauthorizedError('Session not found');
      }
    } catch(e){
      next(e);
    }
  });

  router.post('/getPspToken', express.json(), async (req, res, next) => {
    try{
      logger.info("----------- In AuthProxy Get PSP Token ----------");
      const redis = config.redis;
      const requestBody = req.body;
      if (!requestBody?.sessionId){
        throw getBadRequestError('Session ID is missing');
      }
      const session = await sessionManager.getSession(requestBody.sessionId);
      if(session?.pf_access_token !== undefined){
        const value = await getAuthPassPspToken(session.pf_access_token);
        logger.info("Fetched PSP Token successfully");
        session.additional_info = {...session.additional_info, psp_access_token: value.access_token};
        sessionManager.setSession(requestBody.sessionId, redis.sessionTtl, session);
        logger.info("Stored PSP Token in cached session successfully");
        res.json(value);
      } else {
        logger.error("Unable to retrieve PSP Token: Session not found.");
        throw getUnauthorizedError('Session not found');
      }
    } catch(e){
      next(e);
    }
  });

  const errorHandler: ErrorRequestHandler = (
    err: {statusCode?: number; message?: string; url?: string} | undefined,
    req,
    res,
    next
  ) => {
    if (err && err.statusCode) {
      logger.error(`Error response from ${req.url}: ${err.message || JSON.stringify(err)}`, err, req);
      res.status(err.statusCode).end((nodeEnv === 'develop' && err.message) || undefined);
    } else {
      next(err);
    }
  };

  router.use(errorHandler);

  return router;
}

