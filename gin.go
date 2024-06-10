package helper

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ResponseMessage is a simple function that returns a message in JSON format with a status code for Gin
func ResponseMessage(ctx *gin.Context, code int, message ...string) {
	output := Message{
		Message: strings.Join(message, " "),
	}

	ctx.Writer.Header().Set("Content-Type", "application/json")
	ctx.JSON(code, output)
}

// BadRequest is a simple function that returns a bad request message in JSON format with a BadRequest status code for Gin
func BadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": message})
}
