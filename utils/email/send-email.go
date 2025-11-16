package email

import (
	"log"
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
		log.Fatalln("RESEND_API_KEY environment variable is not set")
	}
	client := resend.NewClient(apiKey)

	return &EmailService{
		from:   os.Getenv("EMAIL_FROM"),
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
