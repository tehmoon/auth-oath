package main

import (
	"strconv"
	"os/exec"
	"log"
	"encoding/json"
	"flag"
	"os"
	"fmt"
	"os/signal"
	"time"
	"net"
	"io/ioutil"
	"github.com/tehmoon/errors"
	"os/user"
)

type User struct {
	Name string `json:"user"`
	Key string `json:"key"`
	accessed time.Time `json:"-"`
	pin string `json:"-"`
}

type OathFlags struct {
	Base32 bool
}

func (u *User) Authorize(password string, flags *OathFlags) (bool) {
	now := time.Now()

	if password == u.pin {
		if now.Sub(u.accessed) <= 24 * time.Hour {
			log.Printf("[+] User %q has logged with same pin", u.Name)
			return true
		}
	}

	ok := authorize(u.Key, password, now, flags)
	if ! ok {
		log.Printf("[-] User %q wrong password", u.Name)
		return false
	}

	u.pin = password
	u.accessed = now

	return true
}

type Users []*User

func (uu Users) Authorize(message *IngoingMessage, flags *OathFlags) (bool) {
	for _, u := range uu {
		if u.Name == message.Name {
			log.Printf("[+] Found user %q in database", message.Name)

			ok := u.Authorize(message.Password, flags)
			if ok {
				log.Printf("[+] Authorizing user %q in database", message.Name)
				return true
			}

			break
		}
	}

	log.Printf("[-] Couldn't find user %q in database or not authorized", message.Name)

	return false
}

func authorize(key, password string, now time.Time, flags *OathFlags) (bool) {
	if password == "" {
		log.Printf("[-] Password is empty")
		return false
	}

	time := now.UTC().Format(time.RFC3339)

	command := []string{"oathtool",}
	command = append(command, "--totp=sha512")

	// Flags should go to the database so it's user specific
	if flags.Base32 {
		command = append(command, "-b")
	}

	command = append(command, []string{"-d", "8", "-N", time, key, password,}...)

	cmd := exec.Command(command[0], command[1:]...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[E] Error running oathtool: %q", string(output[:]))
		return false
	}

	return true
}

var (
	FlagConfigPath string
	FlagSocketPath string
	FlagSocketUser string
	FlagSocketGroup string
	FlagBase32 bool
	ErrBadFlag error = errors.New("Error bad flag")
)

func init() {
	flag.StringVar(&FlagConfigPath, "config", "", "Path to the user json file")
	flag.StringVar(&FlagSocketPath, "socket", "", "Path to the socket file")
	flag.StringVar(&FlagSocketUser, "user", "", "Set user name on the socket file")
	flag.StringVar(&FlagSocketGroup, "group", "", "Set group name on the socket file")
	flag.BoolVar(&FlagBase32, "base32", false, "Use base32 instead of hex")

	flag.Parse()
}

func main() {
	if FlagConfigPath == "" {
		err := errors.Wrap(ErrBadFlag, "-config cannot be empty")
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(2)
	}

	if FlagSocketPath == "" {
		err := errors.Wrap(ErrBadFlag, "-socket cannot be empty")
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(2)
	}

	flags := &OathFlags{
		Base32: FlagBase32,
	}

	u, g, err := checkUserGroup(FlagSocketUser, FlagSocketGroup)
	if err != nil {
		err = errors.Wrap(err,  "Error in -user or -group flag")
		err = errors.WrapErr(err, ErrBadFlag)
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(2)
	}

	users, err := loadUsers(FlagConfigPath)
	if err != nil {
		err = errors.Wrapf(err, "Error loading config file %q", FlagConfigPath)
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(2)
	}

	err = start(users, u, g, FlagSocketPath, flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())

		os.Exit(1)
	}
}

func checkUserGroup(username, groupname string) (int, int, error) {
	var (
		u, g int = -1, -1
		uu *user.User
		gg *user.Group
		err error
	)

	cu, err := user.Current()
	if err != nil {
		return -1, -1, errors.Wrap(err, "Error getting the current user")
	}

	if username != "" {
		uu, err = user.Lookup(username)
		if err != nil {
			return -1, -1, errors.Wrapf(err, "Error looking up username %q", username)
		}

		cu.Uid = uu.Uid
	}

	if groupname != "" {
		gg, err = user.LookupGroup(groupname)
		if err != nil {
			return -1, -1, errors.Wrapf(err, "Error looking up groupname %q", groupname)
		}

		cu.Gid = gg.Gid
	}

	u, err = strconv.Atoi(cu.Uid)
	if err != nil {
		return -1, -1, errors.Wrapf(err, "Error converting uid string %q to int", cu.Uid)
	}

	g, err = strconv.Atoi(cu.Gid)
	if err != nil {
		return -1, -1, errors.Wrapf(err, "Error converting gid string %q to int", cu.Gid)
	}


	return u, g, nil
}

func removeFile(f string) (error) {
	return os.Remove(f)
}

func start(users Users, u, g int, f string, flags *OathFlags) (error) {
	l, err := listenUnix(u, g, f)
	if err != nil {
		return errors.Wrapf(err, "Error listening on socket %q", f)
	}
	defer l.Close()
	defer removeFile(f)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	accept := acceptUnix(l)

	for {
		select {
			case <-c:
				return nil
			case au := <- accept:
				if au.Err != nil {
					return errors.Wrap(err, "Error accepting the connection")
				}

				log.Printf("[+] New connection\n")

				processAccept(au.UnixConn, users, flags)

				log.Printf("[-] Connection closed\n")
		}
	}

	return nil
}

type IngoingMessage struct {
	Name string `json:"username"`
	Password string `json:"password"`
}

type OutgoingMessage struct {
	Ok bool `json:"ok"`
}

func processAccept(unix *net.UnixConn, users Users, flags *OathFlags) {
	defer unix.Close()

	payload, err := ioutil.ReadAll(unix)
	if err != nil {
		log.Printf("[E] %s\n", errors.Wrap(err, "Error reading from socket"))
		return
	}

	message := &IngoingMessage{}

	err = json.Unmarshal(payload, message)
	if err != nil {
		log.Printf("[E] %s\n", errors.Wrap(err, "Error unmarshaling message from JSON"))
		return
	}

	ok := users.Authorize(message, flags)
	if ok {
		payload, err = json.Marshal(&OutgoingMessage{Ok: true,})
		if err != nil {
			log.Printf("[E] %s\n", errors.Wrap(err, "Error marshaling message from OutgoingMessage"))
			return
		}
	} else {
		payload, err = json.Marshal(&OutgoingMessage{Ok: false,})
		if err != nil {
			log.Printf("[E] %s\n", errors.Wrap(err, "Error marshaling message from OutgoingMessage"))
			return
		}
	}

	_, err = unix.Write(payload)
	if err != nil {
		log.Printf("[E] %s\n", errors.Wrap(err, "Error writing response to socket"))
		return
	}

	return
}

func listenUnix(u, g int, f string) (*net.UnixListener, error) {
	addr := &net.UnixAddr{
		Name: f,
		Net: "unix",
	}

	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, errors.Wrapf(err, "Error listening on socket %q", f)
	}

	err = os.Chown(f, u, g)
	if err != nil {
		l.Close()
		return nil, errors.Wrapf(err, "Error changing owner to \"%d:%d\" on socket %q", u, g, f)
	}

	err = os.Chmod(f, 0660)
	if err != nil {
		l.Close()
		return nil, errors.Wrapf(err, "Error changing permissions to \"0600\" on socket %q", f)
	}

	return l, nil
}

func acceptUnix(l *net.UnixListener) (chan *AcceptUnix) {
	accept := make(chan *AcceptUnix, 0)
	go acceptUnixSync(l, accept)

	return accept
}

func acceptUnixSync(l *net.UnixListener, accept chan *AcceptUnix) {
	for {
		unix, err := l.AcceptUnix()

		accept <- &AcceptUnix{
			UnixConn: unix,
			Err: err,
		}
	}
}

type AcceptUnix struct {
	UnixConn *net.UnixConn
	Err error
}

func readConfigFile(f string) ([]byte, error) {
	err := isRegularFile(f)
	if err != nil {
		return nil, err
	}

	// TODO (tehmoon): Check for permissions

	payload, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading config file")
	}

	return payload, nil
}

func loadUsers(f string) (Users, error) {
	payload, err := readConfigFile(f)
	if err != nil {
		return nil, err
	}

	var uu Users

	err = json.Unmarshal(payload, &uu)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshling from JSON")
	}

	users := make(Users, 0)

	for i, u := range uu {
		if u.Name == "" {
			return nil, errors.Wrapf(err, "Entry %d doesn't have a %q field set", i + 1, "user")
		}

		if u.Key == "" {
			return nil, errors.Wrapf(err, "Entry %d doesn't have a %q field set", i + 1, "key")
		}

		for _, user := range users {
			if user.Name == u.Name {
				return nil, errors.Wrapf(err, "Duplicate user %q found at entry %d", u.Name, i + 1)
			}
		}

		user := &User{}
		*user = *u

		users = append(users, user)
	}

	return users, nil
}

func isRegularFile(f string) (error) {
	fi, err := os.Stat(f)
	if err != nil {
		return errors.Wrap(err, "Error calling os.Stat")
	}

	fm := fi.Mode()
	if ! fm.IsRegular() {
		return errors.New("File is not regular")
	}

	return nil
}
