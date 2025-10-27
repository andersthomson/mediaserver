package main

import (
	"github.com/google/uuid"
)

type requestid uuid.UUID

func NewRequestid() requestid {
	u, err := uuid.NewRandom()
	if err != nil {
		panic(4)
	}
	return requestid(u)
}

func (r requestid) String() string {
	return uuid.UUID(r).String()
}
