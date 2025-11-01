# catharsis-clone
Clone Spotify playlists to your Soundcloud account

## Clone Flow 

1. Spotify Auth 
2. Soundcloud Auth 
3. Obtains playlists tracks from Spotify 
4. Creates a clone of each playlist in Soundcloud



## Instructions 

### Set Up Keys and Redirect URLs

1. Register for a new app with Spotify and add the [Spotify client ID and client secret](https://developer.spotify.com/dashboard) to `secrets.yml`
-  See https://developer.spotify.com/dashboard

2. Register for a new app with Soundcloud and add the Soundcloud client ID and secret to `secrets.yml`


```yaml
SPOTIFY_CLIENT_ID: spotify_clt_id
SPOTIFY_CLIENT_SECRET: spotify_clt_secret
SOUNDCLOUD_CLIENT_ID: soundcloud_clt_id
SOUNDCLOUD_SECRET_ID: soundcloud_clt_secret
```

3. Add the redirect URLs to `secrets.yml` (Note: If you update code, remember to change the redirect config)
```yML
SPOTIFY_REDIRECT_URL: http://127.0.0.1:8080/callback
SOUNDCLOUD_REDIRECT_URI: http://localhost:8080/sc-callback
```



### Run Application 

Paste the following in your terminal after you `cd` into the app path
```go
go run main.go
```


### Visit Site 

Open the following URL in your browser: http://localhost:8080





