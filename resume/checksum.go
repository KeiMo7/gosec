package resume

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// sha256Hex returns the lowercase hex SHA-256 digest of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// checksumConfig computes the integrity checksum of the config file payload
// excluding the checksum field itself.
func checksumConfig(c *configFile) (string, error) {
	clone := *c
	clone.Checksum = ""
	raw, err := json.Marshal(&clone)
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}
