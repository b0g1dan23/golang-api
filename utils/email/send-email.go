package email

import (
	"os"

	"github.com/resend/resend-go/v2"
)

type EmailService struct {
	from   string
	client *resend.Client
}

func NewEmailService() *EmailService {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		return nil
	}

	emailFrom := os.Getenv("EMAIL_FROM")
	if emailFrom == "" {
		return nil
	}

	client := resend.NewClient(apiKey)
	return &EmailService{
		from:   emailFrom,
		client: client,
	}
}

func (es *EmailService) SendEmail(to []string, subject, htmlContent string) error {
	params := &resend.SendEmailRequest{
		From:    es.from,
		To:      to,
		Subject: subject,
		Html:    htmlContent,
	}

	_, err := es.client.Emails.Send(params)
	if err != nil {
		return err
	}

	return nil
}
