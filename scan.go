package hostkeys

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"golang.org/x/crypto/ssh"
)

// TODO: Find a good way to make the timeout configurable
const timeout = time.Second * 5

// DefaultKeyAlgorithms is the default set of algorithms that will be
// attempted by Scan.
var DefaultKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSA,
}

// Scan retrieves a set of public ssh host keys from a remote host.
//
// If key algorithms are provided, only keys using those algorithms will
// be returned. If no key algorithms are provided, DefaultKeyAlgorithms
// will be used.
//
// Entries supported by the remote will be returned in the same order as the
// requested key algorithms.
func Scan(addr string, keyAlgorithms ...string) (entries []Entry, err error) {
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "22")
	}

	if keyAlgorithms == nil {
		keyAlgorithms = DefaultKeyAlgorithms
	}

	// Pre-allocate a slice for the scans to write their entries to
	results := make([]Entry, len(keyAlgorithms))

	// Use a waitgroup to know when all scan calls have completed
	var wg sync.WaitGroup
	wg.Add(len(keyAlgorithms))

	for i, algorithm := range keyAlgorithms {
		go func(i int, algorithm string) {
			defer wg.Done()
			entry, scanErr := scan(addr, algorithm)
			if i == 0 {
				err = scanErr
			}
			if scanErr == nil {
				results[i] = entry
			}
		}(i, algorithm)
	}

	// Wait for the calls to complete
	wg.Wait()

	// Gather valid results into entries
	for i := range results {
		if results[i].Key != nil {
			entries = append(entries, results[i])
		}
	}

	// If we received at least one entry, consider the call a success.
	if len(entries) > 0 {
		return entries, nil
	}

	// Otherwise, hand back the first error we received
	return entries, err
}

func scan(addr string, keyAlgorithm string) (entry Entry, err error) {
	// Some useful notes on ssh dialing can be found here:
	// https://utcc.utoronto.ca/~cks/space/blog/programming/GoSSHHostKeyCheckingNotes

	start := time.Now()

	// Open a TCP connection
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return entry, err
	}
	defer conn.Close()

	// Set a deadline
	conn.SetDeadline(start.Add(timeout))

	// Create the ssh connection and record the server's host key
	var valid bool
	c, _, _, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		HostKeyAlgorithms: []string{keyAlgorithm},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			var addresses []string
			if address := knownhosts.Normalize(hostname); address != "" {
				addresses = append(addresses, address)
			}
			if address := knownhosts.Normalize(remote.String()); address != "" {
				addresses = append(addresses, address)
			}
			if len(addresses) > 0 {
				valid = true
				entry = Entry{
					Addresses: addresses,
					Key:       key,
				}
			}
			return nil
		},
	})
	if err == nil {
		defer c.Close()
	}

	// If we got a host key, ignore all other errors
	if valid {
		return entry, nil
	}

	// If we didn't get a host key, return an error
	if err == nil {
		return entry, errors.New("host key not received")
	}
	return entry, err
}
