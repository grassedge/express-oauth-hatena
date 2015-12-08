"use strict";

var oauth = require('oauth').OAuth;

export class OAuth {
    private _oauth: any;

    constructor(
        requestUrl: string,
        accessUrl: string,
        consumerKey: string,
        consumerSecret: string,
        version: string,
        authorize_callback?: string,
        signatureMethod?: string,
        nonceSize?: string,
        customHeaders?: string
    ) {
        this._oauth = new oauth(
            requestUrl,
            accessUrl,
            consumerKey,
            consumerSecret,
            version,
            authorize_callback,
            signatureMethod,
            nonceSize,
            customHeaders
        )
    }

    getOAuthAccessToken(
        oauthToken: string,
        oauthTokenSecret: string,
        oauthVerifier: string
    ): Promise<any> {
        return new Promise((resolve, reject) => {
            this._oauth.getOAuthAccessToken(
                oauthToken,
                oauthTokenSecret,
                oauthVerifier,
                function(
                    err: any,
                    oauth_access_token: string,
                    oauth_access_token_secret: string,
                    results: any
                ) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            oauth_access_token: oauth_access_token,
                            oauth_access_token_secret: oauth_access_token_secret,
                            results: results
                        })
                    }
                }
            );
        });
    }

    getOAuthRequestToken(extraParams: any): Promise<any> {
        return new Promise((resolve, reject) => {
            this._oauth.getOAuthRequestToken(
                extraParams,
                function(
                    err: any,
                    oauth_token: string,
                    oauth_token_secret: string,
                    results: any
                ) {
                    if (err) {
                        reject({ err: err, code: 500 });
                    } else {
                        resolve({
                            oauth_token: oauth_token,
                            oauth_token_secret: oauth_token_secret,
                            results: results
                        });
                    }
                }
            );
        })
    }

    getProtectedResource(
        url: string,
        method: string,
        oauth_token: string,
        oauth_token_secret: string
    ): Promise<any> {
        return new Promise((resolve, reject) => {
            this._oauth.getProtectedResource(
                url,
                method,
                oauth_token,
                oauth_token_secret,
                function(err: any, data: any, response: any) {
                    if (err) { reject(err) }
                    else { resolve(data); }
                }
            );
        })
    }

};

