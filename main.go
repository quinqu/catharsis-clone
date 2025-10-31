package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
	"gopkg.in/yaml.v2"
)

// Config holds application configuration
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Port         string
}

// SpotifyUser represents user info from Spotify API
type SpotifyUser struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Country     string `json:"country"`
}

// AuthServer handles OAuth flow
type AuthServer struct {
	config               *oauth2.Config
	states               map[string]time.Time // state -> expiry time
	statesMutex          sync.RWMutex
	tokenChannel         chan *oauth2.Token
	token                *oauth2.Token
	soundcloudToken      string
	tokenMutex           sync.RWMutex
	soundCloudTokenMutex sync.RWMutex
	secrets              map[string]string
	secretsMutex         sync.RWMutex
}

// NewAuthServer creates a new authentication server
func NewAuthServer(cfg Config) *AuthServer {
	return &AuthServer{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     spotify.Endpoint,
			Scopes: []string{
				"user-read-email",
				"user-read-private",
				"playlist-read-private",
				"playlist-read-collaborative",
				"playlist-modify-public",
				"playlist-modify-private",
			},
		},
		states:       make(map[string]time.Time),
		tokenChannel: make(chan *oauth2.Token, 1),
	}
}

// generateState creates a secure random state string
func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// saveState stores a state with expiration
func (s *AuthServer) saveState(state string) {
	s.statesMutex.Lock()
	defer s.statesMutex.Unlock()
	s.states[state] = time.Now().Add(5 * time.Minute)
}

// validateState checks if state is valid and removes it
func (s *AuthServer) validateState(state string) bool {
	s.statesMutex.Lock()
	defer s.statesMutex.Unlock()

	expiry, exists := s.states[state]
	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(expiry) {
		delete(s.states, state)
		return false
	}

	// Remove used state (one-time use)
	delete(s.states, state)
	return true
}

// HandleLogin redirects user to Spotify authorization page
func (s *AuthServer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	s.saveState(state)

	authURL := s.config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	log.Printf("Generated state: %s", state)
	log.Printf("Redirecting to Spotify auth URL")

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleCallback processes the OAuth callback from Spotify
func (s *AuthServer) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query()
	state := query.Get("state")
	code := query.Get("code")
	errParam := query.Get("error")

	log.Printf("Callback received from spotify - state: %s", state)

	// Check for errors from Spotify
	if errParam != "" {
		errorMsg := fmt.Sprintf("spotify returned an error: %s", errParam)
		log.Println(errorMsg)
		http.Error(w, errorMsg, http.StatusBadRequest)
		return
	}

	// Validate state
	if !s.validateState(state) {
		log.Println("Invalid or expired state")
		http.Error(w, "Invalid or expired state parameter", http.StatusBadRequest)
		return
	}

	// Check for authorization code
	if code == "" {
		log.Println("missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	log.Println("exchanging authorization code for token...")

	// Exchange code for token
	ctx := context.Background()
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("token obtained successfully!")

	// Get user info to verify token works
	user, err := s.getUserInfo(ctx, token)
	if err != nil {
		log.Printf("failed to get user info: %v", err)
		http.Error(w, fmt.Sprintf("failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("authenticated user: %s (%s)", user.DisplayName, user.Email)

	s.tokenMutex.Lock()
	s.token = token
	s.tokenMutex.Unlock()

	// Send success response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
	<title>Authentication Successful</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			margin: 0;
			background: linear-gradient(135deg, #1DB954 0%%, #191414 100%%);
		}
		.container {
			background: white;
			padding: 40px;
			border-radius: 12px;
			box-shadow: 0 4px 20px rgba(0,0,0,0.3);
			text-align: center;
			max-width: 500px;
		}
		h1 {
			color: #1DB954;
			margin-top: 0;
		}
		.user-info {
			margin: 20px 0;
			padding: 20px;
			background: #f8f9fa;
			border-radius: 8px;
		}
		.user-info p {
			margin: 10px 0;
			color: #333;
		}
		.token {
			font-family: monospace;
			font-size: 12px;
			color: #666;
			word-break: break-all;
			margin-top: 10px;
		}
		.success-icon {
			font-size: 48px;
			margin-bottom: 20px;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="success-icon">✓</div>
		<h1>Authentication Successful!</h1>
		<div class="user-info">
			<p><strong>Welcome, %s!</strong></p>
			<p>Email: %s</p>
			<p>Country: %s</p>
		</div>

		<a href="/clone" class="login-btn">Clone Playlists</a>

		<div class="token">
			<small>Token: %s...</small>
		</div>
	</div>
</body>
</html>
	`, user.DisplayName, user.Email, user.Country, token.AccessToken[:20])

}

// GetToken returns the stored authentication token
func (s *AuthServer) GetToken() *oauth2.Token {
	s.tokenMutex.RLock()
	defer s.tokenMutex.RUnlock()
	return s.token
}

// getUserInfo fetches user information from Spotify API
func (s *AuthServer) getUserInfo(ctx context.Context, token *oauth2.Token) (*SpotifyUser, error) {
	client := s.config.Client(ctx, token)

	resp, err := client.Get("https://api.spotify.com/v1/me")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spotify API returned status %d", resp.StatusCode)
	}

	var user SpotifyUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &user, nil
}

// HandleIndex serves the home page with login button
func (s *AuthServer) HandleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
	<title>Spotify OAuth</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			margin: 0;
			background: linear-gradient(135deg, #1DB954 0%, #191414 100%);
		}
		.container {
			background: white;
			padding: 60px 40px;
			border-radius: 12px;
			box-shadow: 0 4px 20px rgba(0,0,0,0.3);
			text-align: center;
			max-width: 500px;
		}
		h1 {
			color: #191414;
			margin-top: 0;
		}
		.spotify-logo {
			font-size: 64px;
			margin-bottom: 20px;
		}
		.login-btn {
			background: #1DB954;
			color: white;
			border: none;
			padding: 16px 48px;
			border-radius: 24px;
			font-size: 16px;
			font-weight: bold;
			cursor: pointer;
			text-decoration: none;
			display: inline-block;
			margin-top: 20px;
			transition: background 0.3s;
		}
		.login-btn:hover {
			background: #1ed760;
		}
		.info {
			margin-top: 30px;
			padding: 20px;
			background: #f8f9fa;
			border-radius: 8px;
			font-size: 14px;
			color: #666;
		}
		code {
			background: #e9ecef;
			padding: 2px 6px;
			border-radius: 3px;
			font-size: 12px;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="spotify-logo">🎵</div>
		<h1>Spotify OAuth</h1>
		<p>Authenticate with your Spotify account to continue</p>
		<a href="/login" class="login-btn">Login with Spotify</a>
	</div>
</body>
</html>
	`)
}

func (s *AuthServer) HandleSoundcloudCallback(w http.ResponseWriter, r *http.Request) {

	// Extract the code from query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "no code received from soundcloud", http.StatusBadRequest)
		return
	}

	// Verify state matches (should check against stored value in production)
	if state != "test" {
		http.Error(w, "state mismatch from souncloud", http.StatusBadRequest)
		return
	}

	fmt.Printf("soundcloud: received code: %s\n", code)

	// Exchange code for token
	token, err := s.exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	s.soundCloudTokenMutex.Lock()
	s.soundcloudToken = token.AccessToken
	s.soundCloudTokenMutex.Unlock()

	fmt.Printf("successfully authenticated! soundcloud access token: %s, refresh token: %s, expires in %d seconds\n", token.AccessToken, token.RefreshToken, token.ExpiresIn)

	http.Redirect(w, r, "/clone-playlists", http.StatusPermanentRedirect)
}

// Exchange authorization code for access token
func (s *AuthServer) exchangeCodeForToken(code string) (*TokenResponse, error) {
	// Prepare form data
	data := url.Values{}

	s.secretsMutex.Lock()
	data.Set("client_id", s.secrets[SOUNDCLOUD_CLIENT_ID_KEY])
	data.Set("client_secret", s.secrets[SOUNDCLOUD_CLIENT_SECRET_KEY])
	s.secretsMutex.Unlock()

	data.Set("grant_type", "authorization_code")

	data.Set("code", code) // The code from the callback

	// Read the entire file content
	contentBytes, err := os.ReadFile("output.txt")
	if err != nil {
		log.Fatalf("Error reading file: %v\n", err)

	}

	// Convert the byte slice to a string
	fileContent := string(contentBytes)

	fmt.Printf("code verifier in exchange %s\n\n", fileContent)
	data.Set("code_verifier", fileContent)
	data.Set("redirect_uri", "http://localhost:8080/sc-callback")
	data.Set("code_challenge_method", "S256")
	fmt.Println(data.Encode())

	// Create POST request
	req, err := http.NewRequest("POST", "https://secure.soundcloud.com/oauth/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set content type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fmt.Println("req:~~~")
	fmt.Printf("%+v", req)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Check for non-200 status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return &tokenResp, nil
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (s *AuthServer) HandleClone(w http.ResponseWriter, r *http.Request) {
	codeVerifier, err := randomBytesInHex(32)
	if err != nil {
		errorMsg := fmt.Sprintf("unable to create code challenge, error: %s", err)
		log.Println(errorMsg)
		fmt.Fprint(w, errorMsg)
	}

	fmt.Println(codeVerifier)
	filePath := "output.txt"

	// os.WriteFile takes: file path, data as a byte slice, and file permissions
	err = os.WriteFile(filePath, []byte(codeVerifier), 0644)
	if err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

	sha2 := sha256.New()
	io.WriteString(sha2, codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))
	s.secretsMutex.Lock()
	authURL := "https://api.soundcloud.com/connect?" + url.Values{
		"client_id":             {s.secrets[SOUNDCLOUD_CLIENT_ID_KEY]},
		"redirect_uri":          {s.secrets[SOUNDCLOUD_REDIRECT_URI_KEY]},
		"response_type":         {"code"},
		"scope":                 {},
		"state":                 {"test"},        // random string for security
		"code_challenge":        {codeChallenge}, // using PKCE
		"code_challenge_method": {"S256"},
	}.Encode()
	s.secretsMutex.Unlock()

	http.Redirect(w, r, authURL, http.StatusPermanentRedirect)
}

type Playlist struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *AuthServer) getTracksSpotify(playlistID string) ([]SpotifyTrack, error) {
	var tracks []SpotifyTrack
	nextURL := fmt.Sprintf("https://api.spotify.com/v1/playlists/%s/tracks", playlistID)

	for nextURL != "" {
		token := s.GetToken()
		if token == nil {
			return nil, fmt.Errorf("no authentication token available. Please login first.")
		}

		ctx := context.Background()
		client := s.config.Client(ctx, token)

		resp, err := client.Get(nextURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get playlists: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("spotify API returned status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var playlistResp SpotifyPlaylistResponse
		if err := json.Unmarshal(body, &playlistResp); err != nil {
			return nil, err
		}

		for _, item := range playlistResp.Items {
			track := item.Track
			allArtists := make([]string, len(track.Artists))
			for i, artist := range track.Artists {
				allArtists[i] = artist.Name
			}

			var primaryArtist string
			if len(track.Artists) > 0 {
				primaryArtist = track.Artists[0].Name
			}

			tracks = append(tracks, SpotifyTrack{
				Name:       track.Name,
				Artist:     primaryArtist,
				AllArtists: allArtists,
				DurationMs: track.DurationMs,
				Album:      track.Album.Name,
			})
		}

		nextURL = playlistResp.Next
	}

	return tracks, nil
}

type SpotifyPlaylistResponse struct {
	Items []struct {
		Track struct {
			Name       string `json:"name"`
			DurationMs int    `json:"duration_ms"`
			Artists    []struct {
				Name string `json:"name"`
			} `json:"artists"`
			Album struct {
				Name string `json:"name"`
			} `json:"album"`
		} `json:"track"`
	} `json:"items"`
	Next string `json:"next"`
}

type SpotifyTrack struct {
	Name       string   `json:"name"`
	Artist     string   `json:"artist"`
	AllArtists []string `json:"all_artists"`
	DurationMs int      `json:"duration_ms"`
	Album      string   `json:"album"`
}

// getPlaylistsSpotify fetches user's playlists from Spotify
func (s *AuthServer) getPlaylistsSpotify() ([]Playlist, error) {
	token := s.GetToken()
	if token == nil {
		return nil, fmt.Errorf("no authentication token available. Please login first.")
	}

	ctx := context.Background()
	client := s.config.Client(ctx, token)

	resp, err := client.Get("https://api.spotify.com/v1/me/playlists")
	if err != nil {
		return nil, fmt.Errorf("failed to get playlists: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spotify API returned status %d", resp.StatusCode)
	}

	// Parse the response
	var result struct {
		Items []Playlist `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode playlists: %w", err)
	}

	return result.Items, nil
}

const (
	SPOTIFY_CLIENT_ID_KEY        = "SPOTIFY_CLIENT_ID"
	SPOTIFY_CLIENT_SECRET_KEY    = "SPOTIFY_CLIENT_SECRET"
	SPOTIFY_REDIRECT_URL_KEY     = "SPOTIFY_REDIRECT_URL"
	SOUNDCLOUD_CLIENT_ID_KEY     = "SOUNDCLOUD_CLIENT_ID"
	SOUNDCLOUD_CLIENT_SECRET_KEY = "SOUNDCLOUD_SECRET_ID"
	SOUNDCLOUD_REDIRECT_URI_KEY  = "SOUNDCLOUD_REDIRECT_URI"
)

func main() {

	secrets := loadSecrets("./secrets.yml")
	fmt.Printf("%+v", secrets)

	config := Config{
		ClientID:     secrets[SPOTIFY_CLIENT_ID_KEY],
		ClientSecret: secrets[SPOTIFY_CLIENT_SECRET_KEY],
		RedirectURL:  secrets[SPOTIFY_REDIRECT_URL_KEY],
		Port:         "8080",
	}

	fmt.Printf("%+v", config)

	// Create auth server
	authServer := NewAuthServer(config)
	authServer.secretsMutex.Lock()
	authServer.secrets = loadSecrets("./secrets.yml")
	authServer.secretsMutex.Unlock()

	// Setup routes
	http.HandleFunc("/", authServer.HandleIndex)
	http.HandleFunc("/login", authServer.HandleLogin)
	http.HandleFunc("/callback", authServer.HandleCallback)
	http.HandleFunc("/sc-callback", authServer.HandleSoundcloudCallback)
	http.HandleFunc("/clone", authServer.HandleClone)
	http.HandleFunc("/clone-playlists", authServer.HandleClonePlaylists)

	// Print startup info
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   CATHARSIS CLONE SERVER                   ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n🌐 Server running at: https://localhost:%s\n", config.Port)

	// Start server
	log.Fatal(http.ListenAndServe(":"+config.Port /*"cert.pem", "key.pem",*/, nil))
}

func searchSoundCloud(query, scToken string) ([]SoundCloudTrack, error) {

	// Build URL with query parameters
	params := url.Values{}
	params.Add("q", query)
	params.Add("limit", fmt.Sprintf("%d", 10))

	url := "https://api.soundcloud.com/tracks?" + params.Encode()

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "OAuth "+scToken)

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	// var tracks []SoundCloudTrack
	// if err := json.NewDecoder(resp.Body).Decode(&tracks); err != nil {
	// 	return nil, fmt.Errorf("failed to parse response: %v", err)
	// }

	//return tracks, nil

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("TOKEN")
	log.Fatal(scToken)

	fmt.Println("~~~~~~~~~~~~~~~~~~")
	fmt.Println(string(b))
	// var tracks []SoundCloudTrack
	// if err := json.NewDecoder(resp.Body).Decode(&tracks); err != nil {
	// 	return nil, err
	// }

	return nil, nil
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("Could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

type ScoredMatch struct {
	Track SoundCloudTrack `json:"track"`
	Score float64         `json:"score"`
	Title string          `json:"title"`
	User  string          `json:"user"`
	URL   string          `json:"url"`
	ID    int             `json:"id"`
}

func calculateMatchScore(spotifyTrack SpotifyTrack, soundCloudTrack SoundCloudTrack) float64 {
	score := 0.0

	// Compare track names (50 points max)
	nameSimilarity := similarityRatio(
		strings.ToLower(spotifyTrack.Name),
		strings.ToLower(soundCloudTrack.Title),
	)
	score += nameSimilarity * 50

	// Check if artist name appears in SC title or username (30 points)
	artist := strings.ToLower(spotifyTrack.Artist)
	scTitle := strings.ToLower(soundCloudTrack.Title)
	scUser := strings.ToLower(soundCloudTrack.User.Username)

	if strings.Contains(scTitle, artist) || strings.Contains(scUser, artist) {
		score += 30
	}

	// Compare duration (20 points max)
	spotifyDuration := float64(spotifyTrack.DurationMs) / 1000.0
	scDuration := float64(soundCloudTrack.Duration) / 1000.0
	durationDiff := math.Abs(spotifyDuration - scDuration)

	if durationDiff <= 5 {
		score += 20
	} else if durationDiff <= 15 {
		score += 10
	}

	return score
}

// similarityRatio calculates similarity ratio (0.0 to 1.0) between two strings
// Similar to Python's SequenceMatcher.ratio()
func similarityRatio(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	lcs := longestCommonSubsequence(s1, s2)
	totalLen := len(s1) + len(s2)

	return 2.0 * float64(lcs) / float64(totalLen)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// longestCommonSubsequence calculates LCS length between two strings
func longestCommonSubsequence(s1, s2 string) int {
	m, n := len(s1), len(s2)
	if m == 0 || n == 0 {
		return 0
	}

	// Create DP table
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				// if match found, set the value of the largest sequence
				// to the current index being processed
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				// if no match, do not inc current cell
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	return dp[m][n]
}

func loadSecrets(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	secrets := make(map[string]string)
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		log.Fatal(err)
	}
	return secrets
}

func (s *AuthServer) HandleClonePlaylists(w http.ResponseWriter, r *http.Request) {
	playlists, err := s.getPlaylistsSpotify()
	if err != nil {
		log.Println(err)
		http.Error(w, "failed to get spotify playlists", http.StatusInternalServerError)
		return
	}

	playlist := playlists[0]
	tracks, err := s.getTracksSpotify(playlist.ID)
	if err != nil {
		log.Printf("Error getting tracks for playlist %s: %v\n", playlist.ID, err)
	}

	// Search for the tracks in SoundCloud and save those IDs
	var soundcloudTrackIDs []string
	for _, track := range tracks {
		// Search SoundCloud using track name and artist
		searchQuery := fmt.Sprintf("%s %s", track.Name, track.Artist)
		scTrackID, err := s.searchSoundCloudTrack(searchQuery)
		if err != nil {
			log.Printf("soundcloud: unable to find soundcloud track for: %s - %s: %v\n", track.Artist, track.Name, err)
		}
		if scTrackID != "" {
			soundcloudTrackIDs = append(soundcloudTrackIDs, scTrackID)
		}
	}

	if len(soundcloudTrackIDs) == 0 {
		log.Printf("no tracks found on soundcloud for playlist: %s\n", playlist.Name)
	}

	// Create the playlist in SoundCloud and add songs
	scPlaylistID, err := s.createSoundCloudPlaylist(playlist.Name, "generated by Catharsis Clone")
	if err != nil {
		log.Printf("error creating soundcloud playlist %s: %v\n", playlist.Name, err)
	}

	err = s.addTracksToSoundCloudPlaylist(scPlaylistID, soundcloudTrackIDs)
	if err != nil {
		log.Printf("error adding tracks to soundCloud playlist %s: %v\n", playlist.Name, err)
	}

	log.Printf("Successfully cloned playlist: %s (%d/%d tracks)\n",
		playlist.Name, len(soundcloudTrackIDs), len(tracks))

	fmt.Fprintf(w, "\nPlaylist cloning complete!")
}

// searchSoundCloudTrack searches for a track on SoundCloud and returns its ID
func (s *AuthServer) searchSoundCloudTrack(query string) (string, error) {
	s.soundCloudTokenMutex.RLock()
	token := s.soundcloudToken
	s.soundCloudTokenMutex.RUnlock()

	if token == "" {
		return "", fmt.Errorf("no SoundCloud token available")
	}

	// SoundCloud API search endpoint
	searchURL := fmt.Sprintf("https://api.soundcloud.com/tracks?q=%s&limit=1",
		url.QueryEscape(query))

	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "OAuth "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("soundcloud API error: %d - %s", resp.StatusCode, string(body))
	}

	fmt.Println(string(body))
	var soundcloudResp []SoundCloudTrack

	err = json.Unmarshal(body, &soundcloudResp)

	if len(soundcloudResp) == 0 {
		return "", fmt.Errorf("no results found")
	}

	return fmt.Sprintf("%d", soundcloudResp[0].ID), nil
}

// SoundCloudTrack represents basic track info
type SoundCloudTrack struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	Duration     int    `json:"duration"`
	PermalinkURL string `json:"permalink_url"`
	ArtworkURL   string `json:"artwork_url"`
	StreamURL    string `json:"stream_url"`
	Genre        string `json:"genre"`
	User         struct {
		Username string `json:"username"`
	} `json:"user"`
}

// createSoundCloudPlaylist creates a new playlist on SoundCloud
func (s *AuthServer) createSoundCloudPlaylist(name, description string) (string, error) {
	s.soundCloudTokenMutex.RLock()
	token := s.soundcloudToken
	s.soundCloudTokenMutex.RUnlock()

	if token == "" {
		return "", fmt.Errorf("no SoundCloud token available")
	}

	playlistData := map[string]interface{}{
		"playlist": map[string]string{
			"title":       name,
			"description": description,
			"sharing":     "public",
		},
	}

	jsonData, err := json.Marshal(playlistData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.soundcloud.com/playlists",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "OAuth "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create playlist: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return fmt.Sprintf("%d", result.ID), nil
}

// addTracksToSoundCloudPlaylist adds tracks to a SoundCloud playlist
func (s *AuthServer) addTracksToSoundCloudPlaylist(playlistID string, trackIDs []string) error {
	s.soundCloudTokenMutex.RLock()
	token := s.soundcloudToken
	s.soundCloudTokenMutex.RUnlock()

	if token == "" {
		return fmt.Errorf("no SoundCloud token available")
	}

	// Build tracks array
	var tracks []map[string]string
	for _, trackID := range trackIDs {
		tracks = append(tracks, map[string]string{"id": trackID})
	}

	updateData := map[string]interface{}{
		"playlist": map[string]interface{}{
			"tracks": tracks,
		},
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.soundcloud.com/playlists/%s", playlistID)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "OAuth "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to add tracks: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}
