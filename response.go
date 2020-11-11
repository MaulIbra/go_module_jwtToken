package jwtToken

type Response struct {
	Status  	int
	Message 	string
}

func ResponseServe(status int, message string) Response {
	var response Response
	response.Status = status
	response.Message = message
	return response
}
