#!/bin/bash

sudo chown -R isucon.isucon /home/isucon/gocode
go get github.com/sonots/go-sql_metrics
go get github.com/sonots/go-template_metrics
go get github.com/sonots/go-http_metrics
go get github.com/sonots/lltsv
go get github.com/go-martini/martini
go get github.com/go-sql-driver/mysql
#go get github.com/martini-contrib/render
go get github.com/martini-contrib/sessions
go get github.com/sonots/martini-contrib/render
go build -o golang-webapp .
