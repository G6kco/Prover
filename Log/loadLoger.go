package log

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

var Log *zap.Logger

func LoadLogger(env string) {
	var err error

	normalize := strings.ToLower(strings.TrimSpace(env))

	switch normalize {
	case "dev", "development":
		Log, err = zap.NewDevelopment()
	
	case "prod", "production":
		Log, err = zap.NewProduction()
		
	default:
		Log, err = zap.NewProduction()
		normalize = "production"
	}
	
	if err != nil{
		fmt.Println("Error -> Logger failed: ", err.Error())
		return
	}
	
	Log.Info("Logger Initialized")
}
