package main

type User interface {
	IDProvider() string
	UserID() string
}
