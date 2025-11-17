package email

import (
	"fmt"
	"sync"
)

type MockEmailService struct {
	mu sync.Mutex

	SendEmailFunc func(to []string, subject, htmlContent string) error
	Calls         []EmailCall

	ShouldFail bool
	FailError  error
}

type EmailCall struct {
	To          []string
	Subject     string
	HTMLContent string
}

func NewMockEmailService() *MockEmailService {
	return &MockEmailService{
		Calls: make([]EmailCall, 0),
	}
}

func (m *MockEmailService) SendEmail(to []string, subject, htmlContent string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Calls = append(m.Calls, EmailCall{
		To:          to,
		Subject:     subject,
		HTMLContent: htmlContent,
	})

	if m.SendEmailFunc != nil {
		return m.SendEmailFunc(to, subject, htmlContent)
	}

	if m.ShouldFail {
		if m.FailError != nil {
			return m.FailError
		}
		return fmt.Errorf("mock email send failed")
	}

	return nil
}

func (m *MockEmailService) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Calls)
}

func (m *MockEmailService) GetLastCall() *EmailCall {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Calls) == 0 {
		return nil
	}
	return &m.Calls[len(m.Calls)-1]
}

func (m *MockEmailService) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Calls = make([]EmailCall, 0)
	m.ShouldFail = false
	m.FailError = nil
	m.SendEmailFunc = nil
}

func (m *MockEmailService) WasCalledWith(email string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, call := range m.Calls {
		for _, recipient := range call.To {
			if recipient == email {
				return true
			}
		}
	}
	return false
}

func (m *MockEmailService) GetCallsForEmail(email string) []EmailCall {
	m.mu.Lock()
	defer m.mu.Unlock()

	var calls []EmailCall
	for _, call := range m.Calls {
		for _, recipient := range call.To {
			if recipient == email {
				calls = append(calls, call)
				break
			}
		}
	}
	return calls
}
