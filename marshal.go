package hostkeys

import "strings"

// Marshal encodes the given entries as a multiline string compatible with the
// known_hosts format.
func Marshal(entries ...Entry) string {
	var b strings.Builder
	for _, entry := range entries {
		if line := entry.String(); line != "" {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}
