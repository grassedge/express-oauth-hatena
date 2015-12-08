"use strict";

import {OAuth} from './oauth-wrap';
import * as express from 'express';
import * as util from 'util';
import * as url from 'url';

const SITE               = 'https://www.hatena.com';
const REQUEST_TOKEN_PATH = '/oauth/initiate';
const ACCESS_TOKEN_PATH  = '/oauth/token';
const AUTHORIZE_PATH     = 'https://www.hatena.ne.jp/oauth/authorize';
const USER_INFO_URL      = 'http://n.hatena.com/applications/my.json';

function hatenaOAuth(consumer_key: string, consumer_secret: string, opts: any) {

    var options = opts || {};

    var consumer = new OAuth(
        SITE + REQUEST_TOKEN_PATH,
        SITE + ACCESS_TOKEN_PATH,
        consumer_key,
        consumer_secret,
        '1.0',
        null,
        'HMAC-SHA1'
    );

    return async function(req: express.Request, res: express.Response, next: any) {
        let verifier = req.query.oauth_verifier;
        if (!verifier) {
            let requestToken = await consumer.getOAuthRequestToken({
                scope: options.scope,
                oauth_callback: url.format({
                    protocol: req.protocol,
                    host: req.get('host'),
                    pathname: req.originalUrl.split('?')[0],
                    query: { location: req.query.location }
                })
            });
            if (!requestToken) { }
            req.session["hatenaoauth_request_token"] = requestToken;
            res.redirect(
                AUTHORIZE_PATH + '?oauth_token=' +
                    encodeURIComponent(requestToken.oauth_token)
            );
        } else {
            try {
                var accessToken = await consumer.getOAuthAccessToken(
                    req.session["hatenaoauth_request_token"].oauth_token,
                    req.session["hatenaoauth_request_token"].oauth_token_secret,
                    verifier
                );
            } catch (err) {
                res.send(500, util.format(
                    "Could not get an OAuth request token from %s\nMessage: %s", SITE, err
                ))
            }
            delete req.session["hatenaoauth_request_token"]

            try {
                var userInfo = await consumer.getProtectedResource(
                    USER_INFO_URL, 'GET',
                    accessToken.oauth_access_token,
                    accessToken.oauth_access_token_secret
                );
            } catch (err) {
                res.send(500, util.format(
                    "Could not get an OAuth access token from %s\nMessage: %s", SITE, err
                ))
            }

            req.session['hatenaoauth_user_info'] = userInfo
            next()
        }
    }
}

export default hatenaOAuth;
