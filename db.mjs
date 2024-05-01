
import mongoose from 'mongoose'
import dotenv from 'dotenv'
dotenv.config()

mongoose.connect(process.env.DSN);

mongoose.connection
  .on("open", () => console.log("The goose is open"))
  .on("close", () => console.log("The goose is closed"))
  .on("error", (error) => {
    console.log(error);
    process.exit();
})

const Playlist = new mongoose.Schema({
    playlistId: String, // the internal uuid of this playlist
    playlistName: String, // the playlist name
    tracks: [{type: mongoose.Schema.Types.ObjectId, ref: 'Track'}], // all of the tracks
    owner: {type: mongoose.Schema.Types.ObjectId, ref: 'User'}
})

const SpotifyPlaylist = new mongoose.Schema({
    owner: {type: mongoose.Schema.Types.ObjectId, ref: 'SpotifyUser'},
    playlistId: String,
    tracksMap: mongoose.Schema.Types.Mixed,
    playlistName: String
})

const Track = new mongoose.Schema({
    addedBy: String, // who added this song
    name: String,
    artist: String,
    uri: String,
    spotifyUrl: String,
    spotifyId: String
})

const User = new mongoose.Schema({
    playlists: [{type: mongoose.Schema.Types.ObjectId, ref: 'Playlist'}], // which playlists this user owns
    username: String,
    password: String,
    loginToken: String
})

const SpotifyUser = new mongoose.Schema({
    playlists: [{type: mongoose.Schema.Types.ObjectId, ref: 'SpotifyPlaylist'}],
    accessToken: String,
    refreshToken: String,
    expiresAt: Number,
    userId: String,
    displayName: String,
    loginToken: String
})

const SpotifyTrackCache = new mongoose.Schema({
    playlistId: String,
    tracks: [{
        name: String,
        spotifyUrl: String,
        spotifyUri: String,
        artist: String,
        addedBy: String
    }],
    offset: Number,
    limit: Number,
    expireAt: { type: Date, default: new Date(), expires: 60*5 }
})

mongoose.model('Playlist', Playlist)
mongoose.model('User', User)
mongoose.model('Track', Track)
mongoose.model('SpotifyUser', SpotifyUser)
mongoose.model('SpotifyPlaylist', SpotifyPlaylist)
mongoose.model('SpotifyTrackCache', SpotifyTrackCache)
