package main

import (
	"encoding/json"
	"fmt"
	"flag"
	"github.com/tehmoon/errors"
	"io/ioutil"
	"os"
	"net"
)

var (
	FlagSocketPath string
	ErrBadFlag error = errors.New("Error bad flag")
)

type IngoingMessage struct {
	Ok bool `json:"ok"`
}

type OutgoingMessage struct {
	Name string `json:"username"`
	Password string `json:"password"`
}

func init() {
	flag.StringVar(&FlagSocketPath, "socket", "", "Path to the socket file")

	flag.Parse()
}

func main() {
	if FlagSocketPath == "" {
		err := errors.Wrap(ErrBadFlag, "-socket cannot be empty")
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(2)
	}

	err := checkEmptyEnvironment("username", "password")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(2)
	}

	username := os.Getenv("username")
	password := os.Getenv("password")

	err = start(username, password, FlagSocketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(1)
	}
}

func start(username, password, f string) (error) {
	c, err := net.Dial("unix", f)
	if err != nil {
		return errors.Wrapf(err, "Error dialing to unix socket %q", FlagSocketPath)
	}
	defer c.Close()

	conn, ok := c.(*net.UnixConn)
	if ! ok {
		return errors.Wrap(err, "Connection is not unix socket")
	}

	payload, err := json.Marshal(&OutgoingMessage{
		Name: username,
		Password: password,
	})
	if err != nil {
		return errors.Wrap(err, "Error marshaling message to JSON")
	}

	_, err = conn.Write(payload)
	if err != nil {
		return errors.Wrap(err, "Error writing message to socket")
	}

	conn.CloseWrite()

	payload, err = ioutil.ReadAll(conn)
	if err != nil {
		return errors.Wrap(err, "Error reading response from socket")
	}

	message := &IngoingMessage{}

	err = json.Unmarshal(payload, message)
	if err != nil {
		return errors.Wrap(err, "Error unmarshaling response from JSON")
	}

	if ! message.Ok {
		return errors.New("Non authorized")
	}

	return nil
}

func checkEmptyEnvironment(vars ...string) (error) {
	for _, v := range vars {
		e := os.Getenv(v)

		if e == "" {
			return errors.Errorf("Variable %q is empty", v)
		}
	}

	return nil
}
