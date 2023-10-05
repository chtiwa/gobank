package main

import (
	"log"
)

func seedAccount(store Storage, fname, lname, pw string) *Account {
	acc, err := NewAccount(fname, lname, pw)

	if err != nil {
		log.Fatal(err)
	}

	if err := store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}
	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "Jack", "Doe", "password")
}

func main() {
	store, err := NewPostsgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	seedAccounts(store)

	server := NewAPIServer(":3000", store)
	server.Run()
}
