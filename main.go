package main

import (
	"github.com/gin-gonic/gin"
	log "github.com/G6kco/Prover/Log"
	parser "github.com/G6kco/Prover/URLParser"
	"github.com/G6kco/Prover/config"
	routes "github.com/G6kco/Prover/router"
)

func main() {
	env := config.InitENV()	
	log.LoadLogger(env)
	routes.Router(gin.Default())
	parser.URIParser("otpauth://totp/MyApp:user@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp")
}