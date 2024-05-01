import querystring from 'querystring'
import https from 'https'
import mongoose from 'mongoose'

import dotenv from 'dotenv'
dotenv.config()

const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const FRONTEND_HOST = process.env.FRONTEND_HOST

export async function httpPost(authOptions, body) {
    return new Promise(async (resolve) => {
        const http_req = https.request(authOptions, (r) => {
            let full = ''
            r.on('data', (chunk) => {
                full += chunk
            })
            r.on('end', async () => {
                let d = JSON.parse(full)
                resolve(d);
            })
        });
        http_req.write(body);
    })
}

export async function httpGet(authOptions) {
    return new Promise(async (resolve) => {
        https.get(authOptions, (r) => {
            let full = ''
            r.on('data', (chunk) => {
                full += chunk
            })
            r.on('end', async () => {
                let d = JSON.parse(full)
                resolve(d);
            })
        });
    });
}

export async function postAuthRequest(body) {
    return new Promise(async (resolve) => {
        const authOptions = {
            host: 'accounts.spotify.com',
            path: '/api/token',
            method: 'POST',
            port: 443,
            headers: {
                'content-type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + (new Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')),
                'Content-Length': Buffer.byteLength(body)
            },
            json: true
        };
        const res = await httpPost(authOptions, body);
        resolve(res)
    });
}

export function isBadToken(access_token) {
    if(!access_token || !access_token.access_token) {
        return true;
    }
    const expDate = new Date(access_token.expires)
    return expDate <= Date.now()
}

export async function refreshAccessToken(refreshToken) {
    return new Promise(async (resolve) => {
        const body =  querystring.stringify({
            grant_type: 'refresh_token',
            refresh_token: refreshToken
        });

        const result = await postAuthRequest(body)
        resolve(result)
    })
}

export async function getAccessTokenClient(req) {
    const body = querystring.stringify({
        grant_type: "client_credentials"
    })
    const d = await postAuthRequest(body);
    return {
        accessToken: d['access_token'],
        expiresAt: Date.now() + (1000 * 60 * 30),
        type: 'client'
    }
}

export async function getAccessTokenUser(code) {
    return new Promise(async (resolve) => {
        const redirect_uri = FRONTEND_HOST+'/spotifycallback'
        const data = querystring.stringify({
            code: code,
            redirect_uri: redirect_uri,
            grant_type: 'authorization_code'
        });
        const d = await postAuthRequest(data);
        const accessToken = d.access_token
        const refreshToken = d.refresh_token
        const userId = d.user_id

        const accessTokenObj = {
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: Date.now() + (1000 * 60 * 30),
            userId: userId
        }
        resolve(accessTokenObj)
    })
}

export async function querySpotifyPost(user, body, endpoint) {
    return new Promise(async (resolve, reject) => {
        if(user && new Date(user.expiresAt) <= Date.now()) {
            const res = await refreshAccessToken(user.refreshToken)
            user.accessToken = res.access_token
            user.refreshToken = res.refresh_token ? res.refresh_token : user.refreshToken
            user.expiresAt = Date.now() + (1000 * 60 * 30)
            user.save()
        }
        const spotify_url = 'api.spotify.com'
        const body_encoded = JSON.stringify(body)
        const headers = {
            'Authorization': 'Bearer ' + user.accessToken,
            'Content-Length': Buffer.byteLength(body_encoded),
            'Content-Type': 'application/json'
        }

        const options = {
            hostname: spotify_url,
            path: '/v1' + endpoint,
            port: 443,
            method: 'POST',
            headers: headers
        }
        
        const js = await httpPost(options, body_encoded);
        resolve(js)
    });
}

export async function querySpotifyGet(user, endpoint) {
    return new Promise(async (resolve, reject) => {
        if(user && new Date(user.expiresAt) <= Date.now()) {
            const res = await refreshAccessToken(user.refreshToken)
            user.accessToken = res.access_token
            user.refreshToken = res.refresh_token ? res.refresh_token : user.refreshToken
            user.expiresAt = Date.now() + (1000 * 60 * 30)
            user.save()
        }
        const spotify_url = 'api.spotify.com'
        const headers = {
            'Authorization': 'Bearer ' + user.accessToken
        }
        const options = {
            hostname: spotify_url,
            path: '/v1' + endpoint,
            port: 443,
            method: 'GET',
            headers: headers
        }
        const js = await httpGet(options)
        resolve(js)
    })
}

export async function search(access_token, query) {
    return new Promise(async (resolve, reject) => {
        const q = querystring.stringify({
            q: query,
            type: 'track'
        })
        const data = await querySpotifyGet(access_token, '/search?'+q)
        let tracks;
        try {
            tracks = data['tracks']['items'].slice(0,3)
        } catch(e) {
            console.log("ERROR", data)
            resolve({error: e})
            return;
        }
        const details = []
        for(const track of tracks) {
            details.push({
                name: track.name,
                artist: track.artists[0].name,
                uri: track.uri,
                spotifyUrl: track.external_urls?.spotify
            });
        }
        resolve(details)
    });
}