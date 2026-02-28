package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// moderationResult holds the result of an LLM moderation check.
type moderationResult struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
}

const moderationPrompt = `You are a content moderator for a university course review platform.

BLOCK a review if it:
- Is spam or not related to a university course
- Just badmouths a person without explanation (e.g. "Prof is bad", "TAs are useless", "Worst course ever")
- Attacks a person rather than describing what was bad about the teaching or course
- Contains slurs, threats, harassment, illegal or sexually inappropriate content
- Is unintelligible gibberish

APPROVE a review if it:
- States opinions subjectively and gives some explanation or example
- Criticizes teaching, workload, difficulty, or course structure — even harshly — as long as it says WHY
- Is in any language (German, English, French, Italian, etc.)

Examples of bad reviews that should be BLOCKED:
- "Prof is bad."
- "The professor is really stinky and sucks!"
- "Worst course ever."
- "TAs are useless."

Examples of acceptable reviews that should be APPROVED:
- "Did not like the teaching style."
- "Could not follow the prof during the lecture."
- "The TAs did not dive deeper into the material but just repeated the lecture content."
- "The exercise sessions did not help me."
- "The lectures were monotonous because there was no interaction."

The key rule: negative opinions are fine, but they must describe WHAT was bad, not just attack a person. "Prof is boring" → BLOCK. "The lectures were monotonous" → APPROVE.

Positive reviews are always fine even without detailed reasoning.

If you are unsure, APPROVE the review.

Respond with ONLY a JSON object, no other text:
{"approved": true}
or
{"approved": false, "reason": "brief explanation"}

Review to moderate:
`

// moderateReview checks a review against the configured LLM via OpenRouter.
// Fail-open: returns approved=true if LLM is not configured, unavailable, or returns unparseable output.
func moderateReview(reviewText string) moderationResult {
	apiKey := os.Getenv("LLM_API_KEY")
	if apiKey == "" {
		return moderationResult{Approved: true}
	}

	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "anthropic/claude-haiku-4.5"
	}

	baseURL := os.Getenv("LLM_BASE_URL")
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1"
	}

	return moderateWithOpenRouter(apiKey, baseURL, model, reviewText)
}

func moderateWithOpenRouter(apiKey, baseURL, model, reviewText string) moderationResult {
	reqBody := map[string]interface{}{
		"model":      model,
		"max_tokens": 256,
		"messages": []map[string]string{
			{"role": "user", "content": moderationPrompt + reviewText},
		},
	}

	bodyBytes, _ := json.Marshal(reqBody)
	endpoint := strings.TrimRight(baseURL, "/") + "/chat/completions"
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("Moderation: failed to create request: %v", err)
		return moderationResult{Approved: true}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Moderation: request failed: %v", err)
		return moderationResult{Approved: true}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Moderation: failed to read response: %v", err)
		return moderationResult{Approved: true}
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Moderation: API returned %d: %s", resp.StatusCode, string(respBody))
		return moderationResult{Approved: true}
	}

	// Parse OpenAI-compatible response format (used by OpenRouter)
	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		log.Printf("Moderation: failed to parse response: %v", err)
		return moderationResult{Approved: true}
	}

	if len(chatResp.Choices) == 0 {
		log.Printf("Moderation: empty response")
		return moderationResult{Approved: true}
	}

	result := parseModerationJSON(chatResp.Choices[0].Message.Content)
	log.Printf("Moderation: approved=%v reason=%q", result.Approved, result.Reason)
	return result
}

// parseModerationJSON extracts the moderation decision from LLM output.
// Fail-open: returns approved if parsing fails.
func parseModerationJSON(text string) moderationResult {
	text = strings.TrimSpace(text)

	// Try to find JSON in the response (LLM might wrap it in markdown code blocks)
	if idx := strings.Index(text, "{"); idx >= 0 {
		if end := strings.LastIndex(text, "}"); end >= idx {
			text = text[idx : end+1]
		}
	}

	var result moderationResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		log.Printf("Moderation: failed to parse LLM output %q: %v", text, err)
		return moderationResult{Approved: true}
	}

	if !result.Approved && result.Reason == "" {
		result.Reason = "Review did not pass automated screening"
	}

	return result
}

// checkModeration runs moderation and returns the result plus a Fiber error response if blocked.
// Returns (result, nil) if approved, (result, error) if blocked.
func checkModeration(c *fiber.Ctx, reviewText string) (moderationResult, error) {
	result := moderateReview(reviewText)
	if !result.Approved {
		return result, c.Status(422).JSON(fiber.Map{
			"error":      "review_blocked",
			"reason":     result.Reason,
			"moderation": true,
		})
	}
	return result, nil
}

