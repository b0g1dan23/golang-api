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

type EmailSender interface {
	SendEmail(to []string, subject, htmlContent string) error
}

func NewEmailService() *EmailService {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Println("RESEND_API_KEY not set")
		return nil
	}

	emailFrom := os.Getenv("EMAIL_FROM")
	if emailFrom == "" {
		log.Println("EMAIL_FROM not set")
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
