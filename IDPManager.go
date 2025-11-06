package main

import (
	"fmt"
	"net/http"
)

type IDP interface {
	IDPName() string
	ServeMux() *http.ServeMux
	LoginPageFragment(w http.ResponseWriter)
}
type IDPManager struct {
	idps []IDP
}

func NewIDPManager() *IDPManager {
	return &IDPManager{}
}

func (i *IDPManager) Register(idp IDP) {
	i.idps = append(i.idps, idp)
}

func (i IDPManager) ServeMux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, i := range i.idps {
		mux.Handle("/"+i.IDPName()+"/", http.StripPrefix("/"+i.IDPName(), i.ServeMux()))
	}
	return mux
}

func (i IDPManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body><h2>Welcome</h2>\n")
	defer fmt.Fprintf(w, "</body></html>")

	i.idps[0].LoginPageFragment(w)
	if len(i.idps) > 1 {
		fmt.Fprintf(w, "Or<p>\n")
	}
	i.idps[1].LoginPageFragment(w)
}
