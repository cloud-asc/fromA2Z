package recon

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func SendMail(access_token string, from string, to string, subject string, body string, socks int) error {
	client := newHttpClient(socks)

	mailBody := fmt.Sprintf(`{
		"message": {
			"subject": "%s",
			"body": {
				"contentType": "HTML",
				"content": "%s"
			},
			"toRecipients": [
				{
					"emailAddress": {
						"address": "%s"
					}
				}
			]
		},
		"saveToSentItems": "false"
	}`, subject, body, to)

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/sendMail", from)

	req, err := http.NewRequest("POST", url, strings.NewReader(mailBody))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+access_token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	body2, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode == 202 {
		fmt.Printf("[+] Email sent successfully from %s to %s\n", from, to)
		return nil
	}

	return fmt.Errorf("failed to send email (status %d): %s", resp.StatusCode, string(body2))
}
