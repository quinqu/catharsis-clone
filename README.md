# catharsis-clone
Clone Spotify playlists to your Soundcloud account

## Clone Flow 

1. Spotify Auth 
2. Soundcloud Auth 
3. Obtains playlists tracks from Spotify 
4. Creates a clone of each playlist in Soundcloud



## Instructions 

### Set Up Keys and Redirect URLs

1. Register for a new app with Spotify and add the Spotify client ID and client secret to `secrets.yml`
-  See https://developer.spotify.com/dashboard.

2. Register for a new app with Soundcloud and add the Soundcloud client ID and secret to `secrets.yml`
- Contact Soundcloud support for this. 


```yaml
SPOTIFY_CLIENT_ID: spotify_clt_id
SPOTIFY_CLIENT_SECRET: spotify_clt_secret
SOUNDCLOUD_CLIENT_ID: soundcloud_clt_id
SOUNDCLOUD_SECRET_ID: soundcloud_clt_secret
```

3. Add the redirect URLs to `secrets.yml` 
```yML
SPOTIFY_REDIRECT_URL: http://localhost:8080/callback
SOUNDCLOUD_REDIRECT_URI: http://localhost:8080/sc-callback
```



### Run Application 

```go
go run main.go
```


### Visit Site to Clone 

Open the following URL in your browser: http://localhost:8080





