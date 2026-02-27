package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// OAuthConfig holds the configuration for the UniClubs OAuth provider.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	ProviderURL  string // e.g. "https://uniclubs.ch"
	BackendURL   string // e.g. "https://api.coursereview.ch"
	FrontendURL  string // e.g. "https://coursereview.ch"
}

func loadOAuthConfig() OAuthConfig {
	return OAuthConfig{
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		ProviderURL:  strings.TrimRight(os.Getenv("OAUTH_PROVIDER_URL"), "/"),
		BackendURL:   strings.TrimRight(os.Getenv("BACKEND_URL"), "/"),
		FrontendURL:  strings.TrimRight(os.Getenv("FRONTEND_URL"), "/"),
	}
}

// oauthLoginHandler redirects the user to the UniClubs OAuth authorization endpoint.
func oauthLoginHandler(c *fiber.Ctx) error {
	cfg := loadOAuthConfig()
	if cfg.ClientID == "" || cfg.ProviderURL == "" {
		return c.Status(500).JSON(fiber.Map{"error": "OAuth not configured"})
	}

	// The origin query param tells us where to redirect the user after login
	origin := c.Query("origin", "/")

	// Build the state parameter: encodes the origin path
	// UniClubs requires state to be at least 8 characters
	callbackURL := cfg.BackendURL + "/oauth/callback"
	state := base64.RawURLEncoding.EncodeToString([]byte("origin:" + origin))

	authURL := fmt.Sprintf("%s/api/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		cfg.ProviderURL,
		url.QueryEscape(cfg.ClientID),
		url.QueryEscape(callbackURL),
		url.QueryEscape("openid student:verify"),
		url.QueryEscape(state),
	)

	return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
}

// tokenResponse represents the response from the OAuth token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

// userInfoResponse represents the response from the UniClubs userinfo endpoint.
// With scopes "openid student:verify", we get sub + student verification fields.
type userInfoResponse struct {
	Sub             string          `json:"sub"`
	IsStudent       bool            `json:"is_student"`
	StudentVerified bool            `json:"student_verified"`
	University      *universityInfo `json:"university"`
	GraduationYear  *int            `json:"graduation_year"`
	Major           *string         `json:"major"`
}

type universityInfo struct {
	Name      string `json:"name"`
	ShortName string `json:"short_name"`
	Slug      string `json:"slug"`
}

// oauthCallbackHandler handles the OAuth callback, exchanges the code for a token,
// fetches user info, and issues a CourseReview JWT.
func oauthCallbackHandler(c *fiber.Ctx) error {
	cfg := loadOAuthConfig()

	code := c.Query("code")
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Missing authorization code"})
	}

	stateParam := c.Query("state")
	origin := "/"
	if stateParam != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(stateParam)
		if err == nil {
			s := string(decoded)
			if strings.HasPrefix(s, "origin:") {
				origin = strings.TrimPrefix(s, "origin:")
			} else {
				origin = s
			}
		}
	}

	// Exchange authorization code for access token
	callbackURL := cfg.BackendURL + "/oauth/callback"
	tokenURL := cfg.ProviderURL + "/api/oauth/token"

	formData := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {callbackURL},
		"client_id":    {cfg.ClientID},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		log.Printf("OAuth: failed to create token request: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to exchange authorization code"})
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("OAuth: token exchange failed: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to exchange authorization code"})
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("OAuth: failed to read token response: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read token response"})
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("OAuth: token endpoint returned %d: %s", resp.StatusCode, string(body))
		return c.Status(500).JSON(fiber.Map{"error": "Token exchange failed"})
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Printf("OAuth: failed to parse token response: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to parse token response"})
	}

	// Fetch user info
	userInfoURL := cfg.ProviderURL + "/api/oauth/userinfo"
	userReq, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		log.Printf("OAuth: failed to create userinfo request: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch user info"})
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := client.Do(userReq)
	if err != nil {
		log.Printf("OAuth: userinfo request failed: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch user info"})
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		log.Printf("OAuth: failed to read userinfo response: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read user info"})
	}

	if userResp.StatusCode != http.StatusOK {
		log.Printf("OAuth: userinfo endpoint returned %d: %s", userResp.StatusCode, string(userBody))
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch user info"})
	}

	// UniClubs wraps responses in { success: true, data: { ... } }
	var wrapper struct {
		Success bool             `json:"success"`
		Data    userInfoResponse `json:"data"`
	}
	if err := json.Unmarshal(userBody, &wrapper); err != nil {
		log.Printf("OAuth: failed to parse userinfo response: %v, body: %s", err, string(userBody))
		return c.Status(500).JSON(fiber.Map{"error": "Failed to parse user info"})
	}

	userInfo := wrapper.Data
	log.Printf("OAuth: userinfo: sub=%q is_student=%v student_verified=%v", userInfo.Sub, userInfo.IsStudent, userInfo.StudentVerified)

	// Determine student status from student:verify scope
	isStudent := userInfo.IsStudent && userInfo.StudentVerified

	// Sign a CourseReview JWT with the same format DecodeJWT() expects
	jwt, err := SignJWT(userInfo.Sub, isStudent)
	if err != nil {
		log.Printf("OAuth: failed to sign JWT: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create session"})
	}

	// Redirect to frontend /tokenset with JWT and origin
	redirectURL := fmt.Sprintf("%s/tokenset?jwt=%s&origin=%s",
		cfg.FrontendURL,
		url.QueryEscape(jwt),
		url.QueryEscape(origin),
	)

	return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
}

// SignJWT creates an RS256-signed JWT with the same {student, exp, unique_id} claims
// that DecodeJWT() already verifies. Uses JWT_PRIVATE_KEY env var (PEM-encoded RSA private key).
func SignJWT(uniqueID string, isStudent bool) (string, error) {
	privKeyPEM := os.Getenv("JWT_PRIVATE_KEY")
	if privKeyPEM == "" {
		return "", fmt.Errorf("JWT_PRIVATE_KEY not set")
	}

	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from JWT_PRIVATE_KEY")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format as fallback
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// Header
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Payload — matches the TokenProperties struct exactly
	payload := map[string]interface{}{
		"student":   isStudent,
		"exp":       time.Now().Add(72 * time.Hour).Unix(), // 3 days, same as PHP script
		"unique_id": uniqueID,
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign
	signingInput := headerB64 + "." + payloadB64
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}
