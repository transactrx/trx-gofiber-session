package gofiber_session

type Session struct {
	Test string
}

func (s *Session) GetTest() string {
	return s.Test
}
