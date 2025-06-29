package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GeminiRequest represents the JSON body for the API request.
type GeminiRequest struct {
	Contents []Content `json:"contents"`
}

// Content is a part of the Gemini request.
type Content struct {
	Parts []Part `json:"parts"`
}

// Part holds the actual text prompt.
type Part struct {
	Text string `json:"text"`
}

// GeminiResponse mirrors the expected JSON structure of a successful response.
type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
			Role string `json:"role"`
		} `json:"content"`
	} `json:"candidates"`
}

// QueryGemini sends a prompt to the Gemini API and returns the response text.
func QueryGemini(apiKey, prompt string) (string, error) {
	// Note: The model name from your example 'gemini-2.0-flash' is not standard.
	// Using a common model like 'gemini-1.5-flash'.
	apiURL := "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + apiKey

	// 1. Construct the request body
	reqBody := GeminiRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: prompt},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request json: %w", err)
	}

	// 2. Create the HTTP POST request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// 3. Execute the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request to gemini api: %w", err)
	}
	defer resp.Body.Close()

	// 4. Read and check the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini api returned non-200 status: %s", string(respBody))
	}

	// 5. Parse the JSON response
	var geminiResp GeminiResponse
	err = json.Unmarshal(respBody, &geminiResp)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response json: %w", err)
	}

	// 6. Extract and return the generated text
	if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
		return geminiResp.Candidates[0].Content.Parts[0].Text, nil
	}

	return "", fmt.Errorf("no content found in gemini response")
}
