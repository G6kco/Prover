package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func InitENV() string {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error -> Failed to load env")
		return "" 
	}
	
	env := os.Getenv("ENV")
	if env == ""{
		fmt.Println("Error -> Failed to get environment")
		return ""
	}
	
	return env
}