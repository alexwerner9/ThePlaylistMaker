import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url';
import session from 'express-session'
import MongoStore from 'connect-mongo'
import {v4 as uuidv4, validate } from 'uuid'
import mongoose from 'mongoose'
import cors from 'cors'
import mongoSanitize from 'express-mongo-sanitize'

import * as spotifyClient from './spotify.mjs'
import './db.mjs'

import bcrypt from 'bcryptjs';

const CLIENT_ID = process.env.CLIENT_ID
const HOSTNAME = process.env.HOSTNAME
const PROTOCOL = process.env.PROTOCOL
const FRONTEND_HOST = process.env.FRONTEND_HOST

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const Playlist = mongoose.model('Playlist');
const SpotifyPlaylist = mongoose.model('SpotifyPlaylist');
const User = mongoose.model('User');
const SpotifyUser = mongoose.model('SpotifyUser')
const SpotifyTrackCache = mongoose.model('SpotifyTrackCache')
const Track = mongoose.model('Track')

app.use(cors({
    origin: [FRONTEND_HOST, 'https://alex-werner.com'],
    credentials: true
}))
app.use(express.json());
app.use(mongoSanitize());
app.use(express.urlencoded({extended: true}))
app.use(express.static(__dirname + '/public'))
app.set('view engine', 'hbs')
app.use(session({
    secret: 'my secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 1000* 60 * 60 *24 * 365
    },
    store: MongoStore.create({
        client: mongoose.connection.getClient(),
        dbName: 'aitplaylistmaker',
        collectionName: "sessions",
        stringify: false,
        autoRemove: "interval",
        autoRemoveInterval: 1
    })
}))

function e(fn) {
    return async (req, res, next) => {
        try {
            await fn(req, res, next)
        } catch (e) {
            console.log("There was an error!", e)
        }
    }
}

app.use(e(async (req, res, next) => {
    if(spotifyClient.isBadToken(req.session.client_access_token)) {
        req.session.client_access_token = await spotifyClient.getAccessTokenClient(req, res)
    }
    if(!req.session.recentlyContributed) {
        req.session.recentlyContributed = {}
    }
    next();
}))

app.post('/login', e(async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const user = await User.findOne({username: username});
    if(!user) {
      res.json({error: "User not found"})
      return;
    }
    if(!bcrypt.compareSync(password, user.password)) {
      res.json({error: "Password incorrect"})
      return;
    }
    res.json({loginToken: user.loginToken})
}))

app.post('/createaccount', e(async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const existingUser = await User.findOne({username: username})
    if(existingUser) {
        res.json({error: "User already exists."})
        return;
    } else {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);
        const loginToken = uuidv4();
        const createdUser = await User.create({username: username, password: hash, loginToken: loginToken})
        res.json(createdUser);
    }
}))

app.get('/getplaylists/:loginToken', e(async (req, res) => {
    const isSpotifyUser = req.query.isSpotifyUser
    const loginToken = req.params.loginToken;
    if(isSpotifyUser == 'true') {
        res.redirect('/getplaylistsspotify?loginToken='+loginToken)
        return
    }
    let user = await User.findOne({loginToken: loginToken}).populate('playlists')
    res.json(user.playlists)
}))

app.get('/getplaylist', e(async (req, res) => {
    const playlistId = req.query.playlistId;
    const loginToken = req.query.loginToken;
    if(!validate(playlistId)) {
        res.redirect('/getplaylistspotify?playlistId='+playlistId+'&loginToken='+loginToken)
        return
    }
    let playlist = await Playlist.findOne({playlistId: playlistId}).populate('tracks')
    if(!playlist) {
        playlist = await Playlist.findOne({playlistUuid: playlistId}).populate('tracks')
    }
    const user = await User.findOne({loginToken: loginToken}).populate('playlists')
    let isOwner = false;
    if(user) {
        isOwner = user.playlists.reduce((prev, curr) => {
            return prev || curr.playlistId == playlistId
        }, false)
    }
    const finalPlaylist = {
        playlistId: playlist.playlistId,
        playlistName: playlist.playlistName,
        tracks: playlist.tracks,
    }
    res.json({playlist: finalPlaylist, isOwner: isOwner, type: 'tpm'})
}))

app.get('/getusername/:loginToken', e(async (req, res) => {
    const loginToken = req.params.loginToken;
    const user = await User.findOne({loginToken: loginToken})
    res.json(user);
}))

app.post('/createplaylist', e(async (req, res) => {
    const isSpotifyUser = req.body.isSpotifyUser
    if(isSpotifyUser) {
        res.redirect(307, '/createplaylistspotify')
        return
    }
    const user = await User.findOne({loginToken: req.body.loginToken});
    if(!user) {
        res.json({error: "You are not logged in."})
        return
    }
    const playlistName = req.body.playlistName;
    const playlistId = uuidv4()
    const createdPlaylist = await Playlist.create({playlistName: playlistName, playlistId: playlistId})
    await user.playlists.push(createdPlaylist)
    user.save()
    res.json(createdPlaylist)
}))

app.post('/deleteplaylist', e(async (req, res) => {
    const user = await User.findOne({loginToken: req.body.loginToken}).populate('playlists')
    if(!user) {
        const spotifyPlaylist = await SpotifyPlaylist.findOne({playlistId: req.body.playlistId}).populate('owner')
        if(spotifyPlaylist && spotifyPlaylist.owner.loginToken == req.body.loginToken) {
            await SpotifyPlaylist.findOneAndDelete({playlistId: req.body.playlistId})
            res.json({success: 'Success'})
        } else {
            res.json({error: 'Not the playlist owner.'})
        }
        return;
    }
    for(const playlist of user.playlists) {
        if(playlist.playlistId == req.body.playlistId) {
            for(const track of playlist.tracks) {
                await Track.findOneAndDelete({_id: track})
            }
            await Playlist.deleteOne({playlistId: playlist.playlistId})
        }
    }
    res.json({success: 'Success'})
}))

app.get('/search', e(async (req, res) => {
    const r = await spotifyClient.search(req.session.client_access_token, req.query.name)
    res.send(r)
}))

app.post('/addsong', e(async (req, res) => {
    const playlistId = req.body.playlistId;
    if(!validate(playlistId)) {
        res.redirect(307, '/addsongspotify')
        return
    }
    const songName = req.body.name;
    const songArtist = req.body.artist;
    const songUri = req.body.uri;
    const addedBy = req.body.addedBy;
    const spotifyUrl = req.body.spotifyUrl;
    const playlist = await Playlist.findOne({playlistId: playlistId})
    const newTrack = await Track.create({name: songName, artist: songArtist, uri: songUri, spotifyUrl: spotifyUrl, addedBy: addedBy})
    playlist.tracks.push(newTrack);
    playlist.save()
    req.session.recentlyContributed[playlist.playlistId] = {
        name: playlist.playlistName,
        timestamp: Date.now()
    }
    req.session.save()
    res.json({success: 'Success'})
}))

app.get('/recentlycontributed', e(async (req, res) => {
    const recentlyContributed = req.session.recentlyContributed || {}
    const resp = []
    for(const playlistId in recentlyContributed) {
        const playlist = recentlyContributed[playlistId]
        console.log(playlist)
        const playlistName = playlist.name
        const timestamp = playlist.timestamp
        resp.push({playlistId: playlistId, playlistName: playlistName, timestamp: timestamp})
    }
    resp.sort((a,b) => {
        return b.timestamp - a.timestamp
    })
    res.json(resp)
}))

////////////////////////////

app.get('/spotifylogin', e((req, res) => {
    const state = '1234567812345678';
    const scope = 'user-read-private playlist-modify-public playlist-modify-private playlist-read-private playlist-read-collaborative';
  
    res.redirect('https://accounts.spotify.com/authorize?' +
        querystring.stringify({
            response_type: 'code',
            client_id: CLIENT_ID,
            scope: scope,
            redirect_uri: `${PROTOCOL}://${HOSTNAME}/`,
            state: state
        })
    );
}));

app.get('/registerspotify', e(async (req, res) => {
    // this should take an access token, a refresh token and a user id
    // register the user. store the info in a new SpotifyUser
    // object. put a reference to this user in our session info
    const code = req.query.code
    const authObj = await spotifyClient.getAccessTokenUser(code)
    const accessToken = authObj.accessToken
    const refreshToken = authObj.refreshToken
    const expiresAt = authObj.expiresAt
    const userInfo = await spotifyClient.querySpotifyGet({
        accessToken: accessToken,
        expiresAt: expiresAt,
        refreshToken: refreshToken
    }, '/me')
    const userId = userInfo.id

    const existingSpotifyUser = await SpotifyUser.findOne({userId: userId})
    let loginToken = uuidv4();

    if(existingSpotifyUser) {
        loginToken = existingSpotifyUser.loginToken
        existingSpotifyUser.accessToken = accessToken
        existingSpotifyUser.refreshToken = refreshToken
        existingSpotifyUser.expiresAt = expiresAt
        existingSpotifyUser.save()
    } else {
        const newSpotifyUser = await SpotifyUser.create({
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: expiresAt,
            userId: userId,
            loginToken: loginToken
        })
    }
    res.json({userId: `${userId}`, loginToken: loginToken})
}))

app.post('/createplaylistspotify', e(async (req, res) => {
    const loginToken = req.body.loginToken
    const playlistName = req.body.playlistName
    const spotifyUser = await SpotifyUser.findOne({loginToken: loginToken})
    if(!spotifyUser) {
        res.json({error: "You are not signed in."})
        return
    }
    const path = `/users/${spotifyUser.userId}/playlists`
    const response = await spotifyClient.querySpotifyPost(spotifyUser, {
        name: playlistName,
        description: "Made via theplaylistmaker.com"
    }, path)
    const playlistId = response.id
    const newPlaylist = await SpotifyPlaylist.create({
        playlistId: playlistId,
        owner: spotifyUser,
        tracksMap: {},
        playlistName: playlistName
    })
    spotifyUser.playlists.push(newPlaylist)
    spotifyUser.save()
    res.json({
        playlistId: playlistId,
        isOwner: spotifyUser.loginToken == loginToken
    })
}))

app.get('/getplaylistspotify', e(async (req, res) => {
    const playlistId = req.query.playlistId
    const loginToken = req.query.loginToken
    const playlist = await SpotifyPlaylist.findOne({playlistId: playlistId}).populate('owner')
    if(!playlist) {
        res.json({error: "Playlist not found."})
        return
    }
    const response = await spotifyClient.querySpotifyGet(playlist.owner, `/playlists/${playlistId}`)
    const tracks = response.tracks.items.map((val) => {
        const track = val.track
        return {
            name: track.name,
            spotifyUrl: track.external_urls?.spotify,
            spotifyUri: track.uri,
            artist: track.artists[0].name,
            addedBy: "Anonymous"
        }
    })
    let tracksMap = playlist.tracksMap
    if(!tracksMap) {
        tracksMap = {}
    }
    const tracksMapClone = structuredClone(tracksMap);
    for(const track of tracks) {
        const addedByList = tracksMapClone[track.spotifyUri]
        if(!addedByList) continue
        const addedByTrack = addedByList[0]
        if(addedByTrack) {
            track.addedBy = addedByTrack
            tracksMapClone[track.spotifyUri].shift()
        }
    }
    res.json({
        isOwner: loginToken == playlist.owner.loginToken,
        playlist: {
            playlistName: response.name,
            tracks: tracks,
            numTracks: response.tracks.total
        },
        type: 'spotify'
    })
}))

app.post('/addsongspotify', e(async (req,res) => {
    const playlistId = req.body.playlistId
    const songUri = req.body.uri
    const addedBy = req.body.addedBy
    const playlist = await SpotifyPlaylist.findOne({playlistId: playlistId}).populate('owner')

    const resp = await spotifyClient.querySpotifyPost(playlist.owner, {
        uris: [songUri]
    }, `/playlists/${playlistId}/tracks`)

    if(!playlist.tracksMap) {
        playlist.tracksMap = {}
    }
    if(!playlist.tracksMap[songUri]) {
        playlist.tracksMap[songUri] = []
    }
    playlist.tracksMap[songUri].push(addedBy)
    playlist.markModified('tracksMap')
    playlist.save()
    req.session.recentlyContributed[playlist.playlistId] = {
        name: playlist.playlistName,
        timestamp: Date.now()
    }
    await req.session.save()
    await SpotifyTrackCache.deleteMany({playlistId: playlist.playlistId})
    res.json(resp)
}))

app.get('/getplaylistsspotify', e(async (req, res) => {
    const loginToken = req.query.loginToken
    const user = await SpotifyUser.findOne({loginToken: loginToken}).populate('playlists')
    res.json(user.playlists)
}))

app.get('/gettracksspotify', e(async (req, res) => {
    const offset = req.query.offset
    const limit = req.query.limit
    const playlistId = req.query.playlistId
    console.log(limit)
    const cachedResp = await SpotifyTrackCache.findOne({playlistId: playlistId, offset: offset, limit: limit})
    if(cachedResp) {
        console.log("CACHE HIT")
        res.json(cachedResp.tracks)
        return
    }
    console.log("CACHE MISS")
    const playlist = await SpotifyPlaylist.findOne({playlistId: playlistId}).populate('owner')
    const url = `/playlists/${playlistId}/tracks?offset=${offset}&limit=${limit}`
    const resp = await spotifyClient.querySpotifyGet(playlist.owner, url)
    const tracks = resp.items.map((val) => {
        const track = val.track
        return {
            name: track.name,
            spotifyUrl: track.external_urls?.spotify,
            spotifyUri: track.uri,
            artist: track.artists[0].name,
            addedBy: "Anonymous"
        }
    })
    let tracksMap = playlist.tracksMap
    if(!tracksMap) {
        tracksMap = {}
    }
    const tracksMapClone = structuredClone(tracksMap);
    for(const track of tracks) {
        const addedByList = tracksMapClone[track.spotifyUri]
        if(!addedByList) continue
        const addedByTrack = addedByList[0]
        if(addedByTrack) {
            track.addedBy = addedByTrack
            tracksMapClone[track.spotifyUri].shift()
        }
    }
    // don't want to cache the last bit, because it can change more frequently
    console.log("TOTAL", resp.total)
    if(limit + offset < resp.total) {
        await SpotifyTrackCache.create({
            offset: offset,
            limit: limit,
            tracks: tracks,
            playlistId: playlistId
        })
    }
    res.json(tracks)
}))


app.get('/alexwerner/test', e(async (req, res) => {
    res.json({result: 'success'})
}))


app.listen(process.env.PORT || 3000);
