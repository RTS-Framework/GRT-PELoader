package main

import (
	"fmt"
	"log"
	"time"

	"github.com/RTS-Framework/Gleam-RT/runtime/storage"
	"github.com/RTS-Framework/Gleam-RT/runtime/watchdog"
)

const imsIDSession = 1

// if the Beacon dead because the program reason, runtime will
// restart it if set the Watchdog.
//
// it can try to get session from In-Memory Storage first,
// not login at once, and the remote Controller is insensible.

func main() {
	session := getSession()
	if len(session) == 0 {
		newSession := login()
		setSession(newSession)
		session = newSession
	}
	fmt.Println("current session:", session)

	// for detect faster
	if !watchdog.IsEnabled() {
		watchdog.SetTimeout(3 * time.Second)
	}

	err := watchdog.Enable()
	if err != nil {
		panic(err)
	}

	// simulate program internal error
	for i := 0; i < 3; i++ {
		err = watchdog.Kick()
		if err != nil {
			panic(err)
		}
		time.Sleep(time.Second)
	}
	fmt.Println("internal error occurred")
	time.Sleep(time.Hour)
}

// new login session like Beacon
func login() []byte {
	fmt.Println("login!")
	return []byte{0x00, 0x01, 0x02, 0x03}
}

func setSession(session []byte) {
	err := storage.SetValue(imsIDSession, session)
	if err != nil {
		log.Fatalf("failed to set value: %s", err)
	}
}

func getSession() []byte {
	session, err := storage.GetValue(imsIDSession)
	if err != nil {
		return nil
	}
	return session
}
