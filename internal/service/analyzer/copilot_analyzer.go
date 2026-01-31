package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/secure-review/internal/domain"
)

var _ domain.CodeAnalyzer = (*CopilotCodeAnalyzer)(nil)

const (
	// GitHub Copilot API endpoint
	copilotAPIEndpoint = "https://api.githubcopilot.com/chat/completions"
	// Default model for Copilot
	defaultCopilotModel = "gpt-4o"
)

// CopilotCodeAnalyzer implements CodeAnalyzer using GitHub Copilot API
type CopilotCodeAnalyzer struct {
	apiKey string
	model  string
	client *http.Client
}

// NewCopilotCodeAnalyzer creates a new CopilotCodeAnalyzer
func NewCopilotCodeAnalyzer(apiKey, model string) *CopilotCodeAnalyzer {
	if model == "" {
		model = defaultCopilotModel
	}
	return &CopilotCodeAnalyzer{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{},
	}
}

// ChatMessage represents a message in the chat completion request
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest represents the request to Copilot API
type ChatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature float64       `json:"temperature,omitempty"`
}

// ChatCompletionChoice represents a choice in the response
type ChatCompletionChoice struct {
	Index   int         `json:"index"`
	Message ChatMessage `json:"message"`
}

// ChatCompletionResponse represents the response from Copilot API
type ChatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Choices []ChatCompletionChoice `json:"choices"`
}

// AnalyzeCode performs code review using GitHub Copilot
func (a *CopilotCodeAnalyzer) AnalyzeCode(ctx context.Context, request *domain.AnalysisRequest) (*domain.AnalysisResult, error) {
	basePrompt := fmt.Sprintf(`You are an expert code reviewer. Analyze the following %s code and provide:
1. A brief summary of what the code does
2. Any security vulnerabilities found (with severity: critical, high, medium, low, info)
3. Code quality suggestions for improvement
4. An overall quality score from 0-100`, request.Language)

	if request.CustomPrompt != nil && *request.CustomPrompt != "" {
		basePrompt += fmt.Sprintf("\n\nUser specific instructions: %s", *request.CustomPrompt)
	}

	prompt := fmt.Sprintf(`%s

Code to review:
%s

Respond in JSON format with this structure:
{
  "summary": "string",
  "security_issues": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "string",
      "description": "string",
      "line_start": number or null,
      "line_end": number or null,
      "suggestion": "string",
      "cwe": "string or null"
    }
  ],
  "suggestions": ["string"],
  "overall_score": number
}`, basePrompt, request.Code)

	content, err := a.sendRequest(ctx, prompt, "You are an expert code reviewer specializing in security analysis and code quality. Always respond with valid JSON.", 0.3)
	if err != nil {
		return nil, err
	}

	var result domain.AnalysisResult
	content = cleanJSONContent(content)

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse Copilot response: %w", err)
	}

	return &result, nil
}

// AnalyzeSecurity performs security-focused analysis
func (a *CopilotCodeAnalyzer) AnalyzeSecurity(ctx context.Context, request *domain.AnalysisRequest) ([]domain.SecurityIssueInput, error) {
	prompt := fmt.Sprintf(`You are a security expert. Analyze the following %s code for security vulnerabilities.

Focus on:
- SQL injection
- XSS vulnerabilities
- Authentication/authorization issues
- Data exposure
- Input validation problems
- Cryptographic weaknesses
- Injection attacks
- Buffer overflows
- Path traversal
- Insecure configurations

Code to analyze:
%s

Respond in JSON format with an array of security issues:
[
  {
    "severity": "critical|high|medium|low|info",
    "title": "string",
    "description": "string",
    "line_start": number or null,
    "line_end": number or null,
    "suggestion": "string",
    "cwe": "CWE-XXX or null"
  }
]

If no security issues are found, return an empty array: []`, request.Language, request.Code)

	content, err := a.sendRequest(ctx, prompt, "You are a security expert specializing in code vulnerability analysis. Always respond with valid JSON.", 0.2)
	if err != nil {
		return nil, err
	}

	var issues []domain.SecurityIssueInput
	content = cleanJSONContent(content)

	if err := json.Unmarshal([]byte(content), &issues); err != nil {
		return nil, fmt.Errorf("failed to parse Copilot response: %w", err)
	}

	return issues, nil
}

// sendRequest sends a request to the Copilot API
func (a *CopilotCodeAnalyzer) sendRequest(ctx context.Context, userPrompt, systemPrompt string, temperature float64) (string, error) {
	reqBody := ChatCompletionRequest{
		Model: a.model,
		Messages: []ChatMessage{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: userPrompt,
			},
		},
		Temperature: temperature,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", copilotAPIEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Copilot API error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Copilot API error: status %d, body: %s", resp.StatusCode, string(body))
	}

	var chatResp ChatCompletionResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse Copilot response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", domain.ErrAnalysisFailed
	}

	return chatResp.Choices[0].Message.Content, nil
}

// cleanJSONContent removes markdown code blocks from the response
func cleanJSONContent(content string) string {
	content = strings.TrimSpace(content)

	// Remove ```json or ``` prefix
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "\n")
	} else if strings.HasPrefix(content, "```") {
		// Find the first newline after ```
		idx := strings.Index(content, "\n")
		if idx != -1 {
			content = content[idx+1:]
		}
	}

	// Remove trailing ```
	content = strings.TrimSuffix(content, "```")

	return strings.TrimSpace(content)
}
