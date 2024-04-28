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
const CLIENT_SECRET = process.env.CLIENT_SECRET
const HOSTNAME = process.env.HOSTNAME
const PROTOCOL = process.env.PROTOCOL
const LISTEN_PORT = process.env.LISTEN_PORT
const FRONTEND_PORT = process.env.FRONTEND_PORT

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const Playlist = mongoose.model('Playlist');
const SpotifyPlaylist = mongoose.model('SpotifyPlaylist');
const User = mongoose.model('User');
const SpotifyUser = mongoose.model('SpotifyUser')
const Track = mongoose.model('Track')

app.use(cors())
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
        console.log(loginToken + "HELLO")
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
    res.json({playlist: playlist, isOwner: isOwner, type: 'tpm'})
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
    res.json({success: 'Success'})
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
    const loginToken = uuidv4();

    if(existingSpotifyUser) {
        existingSpotifyUser.accessToken = accessToken
        existingSpotifyUser.refreshToken = refreshToken
        existingSpotifyUser.expiresAt = expiresAt
        existingSpotifyUser.loginToken = loginToken
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
    console.log("RES", response)
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
    console.log(response)
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

    console.log(playlist)
    if(!playlist.tracksMap) {
        playlist.tracksMap = {}
    }
    if(!playlist.tracksMap[songUri]) {
        playlist.tracksMap[songUri] = []
    }
    playlist.tracksMap[songUri].push(addedBy)
    playlist.markModified('tracksMap')
    playlist.save()
    res.json(resp)
}))

app.get('/getplaylistsspotify', e(async (req, res) => {
    const loginToken = req.query.loginToken
    const user = await SpotifyUser.findOne({loginToken: loginToken}).populate('playlists')
    console.log(user.playlists)
    res.json(user.playlists)
}))

app.get('/gettracksspotify', e(async (req, res) => {
    const offset = req.query.offset
    const limit = req.query.limit
    console.log(limit, offset)
    const playlistId = req.query.playlistId
    const playlist = await SpotifyPlaylist.findOne({playlistId: playlistId}).populate('owner')
    const url = `/playlists/${playlistId}/tracks?offset=${offset}&limit=${limit}`
    const resp = await spotifyClient.querySpotifyGet(playlist.owner, url)
    console.log("RESP", resp)
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
    console.log(tracks)
    res.json(tracks)
}))


app.listen(process.env.PORT || 3000);
