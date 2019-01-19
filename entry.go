package hostkeys

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Entry is an ssh host key.
type Entry struct {
	Addresses []string
	Key       ssh.PublicKey
}

// String returns a string representation of the host key that's compatible
// with the known_hosts file format. The format is defined here:
// http://man.openbsd.org/sshd.8
func (e Entry) String() string {
	return knownhosts.Line(e.Addresses, e.Key)
	/*
		var buf [2]string
		var hosts = buf[:0]

		if host, _, err := net.SplitHostPort(hk.Hostname); err == nil {
			hosts = append(hosts, host)
		}

		if hk.Remote != nil {
			if host, _, err := net.SplitHostPort(hk.Remote.String()); err == nil {
				hosts = append(hosts, host)
			}
		}

		if len(hosts) == 0 {
			return ""
		}

		return fmt.Sprintf("%s %s", strings.Join(hosts, ","), ssh.MarshalAuthorizedKey(hk.Key))
	*/
}
