package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	macsecCtlEtherType         = 0x88b5
	macsecCtlMagic             = "SPRMSEC1"
	macsecCtlDisable      byte = 1
	macsecCtlAck          byte = 2
	macsecCtlChallengeLen      = 16
	macsecCtlMACLen            = 32
	macsecCtlPayloadLen        = len(macsecCtlMagic) + 1 + macsecCKNLen + macsecCtlChallengeLen + macsecCtlMACLen
	macsecCtlFrameLen          = 14 + macsecCtlPayloadLen
	macsecCtlAckWait           = 10 * time.Second
)

var errMACsecCtlNoAck = errors.New("mesh node did not acknowledge")

type macsecCtlKeys struct {
	Nonce string
	CKN   []byte
	Key   []byte
}

func deriveMACsecCtlKeys(secret string, nonceHex string) (macsecCtlKeys, error) {
	keys, err := deriveMACsecKeys(secret, nonceHex)
	if err != nil {
		return macsecCtlKeys{}, err
	}
	nonce, _ := decodeMACsecNonce(nonceHex)
	key, err := hkdf.Key(sha256.New, []byte(secret), nonce, macsecKDFLabel+" ctl", 32)
	if err != nil {
		return macsecCtlKeys{}, err
	}
	return macsecCtlKeys{Nonce: nonceHex, CKN: keys.CKN, Key: key}, nil
}

func macsecCtlTag(keys macsecCtlKeys, cmd byte, challenge []byte) []byte {
	mac := hmac.New(sha256.New, keys.Key)
	mac.Write([]byte(macsecCtlMagic))
	mac.Write([]byte{cmd})
	mac.Write(keys.CKN)
	mac.Write(challenge)
	return mac.Sum(nil)
}

func newMACsecChallenge() ([]byte, error) {
	challenge := make([]byte, macsecCtlChallengeLen)
	_, err := rand.Read(challenge)
	return challenge, err
}

func buildMACsecCtlFrame(dst, src net.HardwareAddr, cmd byte, keys macsecCtlKeys, challenge []byte) []byte {
	frame := make([]byte, 0, macsecCtlFrameLen)
	frame = append(frame, dst...)
	frame = append(frame, src...)
	frame = binary.BigEndian.AppendUint16(frame, macsecCtlEtherType)
	frame = append(frame, macsecCtlMagic...)
	frame = append(frame, cmd)
	frame = append(frame, keys.CKN...)
	frame = append(frame, challenge...)
	return append(frame, macsecCtlTag(keys, cmd, challenge)...)
}

func parseMACsecCtlFrame(frame []byte, keys macsecCtlKeys) (cmd byte, src net.HardwareAddr, challenge []byte, ok bool) {
	if len(frame) < macsecCtlFrameLen || len(keys.CKN) != macsecCKNLen || len(keys.Key) == 0 {
		return 0, nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != macsecCtlEtherType {
		return 0, nil, nil, false
	}
	p := frame[14:macsecCtlFrameLen]
	if string(p[:len(macsecCtlMagic)]) != macsecCtlMagic {
		return 0, nil, nil, false
	}
	p = p[len(macsecCtlMagic):]
	cmd = p[0]
	ckn := p[1 : 1+macsecCKNLen]
	challenge = p[1+macsecCKNLen : 1+macsecCKNLen+macsecCtlChallengeLen]
	tag := p[1+macsecCKNLen+macsecCtlChallengeLen:]
	if !bytes.Equal(ckn, keys.CKN) {
		return 0, nil, nil, false
	}
	if !hmac.Equal(tag, macsecCtlTag(keys, cmd, challenge)) {
		return 0, nil, nil, false
	}
	src = append(net.HardwareAddr{}, frame[6:12]...)
	return cmd, src, append([]byte{}, challenge...), true
}

const macsecCtlAckWindow = 30 * time.Second

func (m *macsecManager) ctlKeys() *macsecCtlKeys {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leafCtl != nil && !m.ctlOffAt.IsZero() && m.now().Sub(m.ctlOffAt) > macsecCtlAckWindow {
		m.leafCtl = nil
	}
	if m.leafCtl == nil {
		m.ctlRunning = false
		return nil
	}
	keys := *m.leafCtl
	return &keys
}

func (m *macsecManager) ctlListen(wanif string) {
	for m.ctlKeys() != nil {
		err := m.sys.RecvFrames(wanif, 3*time.Second, func(frame []byte) bool {
			m.handleLeafCtl(wanif, frame)
			return false
		})
		if err != nil && !errors.Is(err, errMACsecCtlNoAck) {
			time.Sleep(time.Second)
		}
	}
}

func (m *macsecManager) handleLeafCtl(wanif string, frame []byte) bool {
	keys := m.ctlKeys()
	if keys == nil {
		return false
	}
	cmd, src, challenge, ok := parseMACsecCtlFrame(frame, *keys)
	if !ok || cmd != macsecCtlDisable {
		return false
	}
	if info, err := m.sys.LinkInfo(wanif); err == nil {
		m.sys.SendFrame(wanif, buildMACsecCtlFrame(src, info.MAC, macsecCtlAck, *keys, challenge))
	}
	m.mu.Lock()
	first := m.ctlOffAt.IsZero()
	if first {
		m.ctlOffAt = m.now()
	}
	m.mu.Unlock()
	if !first {
		return true
	}
	Configmtx.Lock()
	if config, err := loadMeshConfigChecked(); err == nil && config.LeafMACsec.Enabled && config.LeafMACsec.KeyNonce == keys.Nonce {
		config.LeafMACsec = LeafSideMACsec{}
		saveConfigLocked(config)
	}
	Configmtx.Unlock()
	fmt.Println("[-] macsec: disabled by the main router over the wire")
	m.Kick()
	return true
}

func (m *macsecManager) disableOverWire(leaf LeafRouter) (bool, error) {
	if leaf.MACsec == nil {
		return false, errors.New("no MACsec association")
	}
	keys, err := deriveMACsecCtlKeys(leaf.APIToken, leaf.MACsec.KeyNonce)
	if err != nil {
		return false, err
	}
	info, err := m.sys.LinkInfo(leaf.MACsec.Parent)
	if err != nil {
		return false, err
	}
	challenge, err := newMACsecChallenge()
	if err != nil {
		return false, err
	}
	frame := buildMACsecCtlFrame(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, info.MAC, macsecCtlDisable, keys, challenge)
	if err := m.sys.SendFrame(leaf.MACsec.Parent, frame); err != nil {
		return false, err
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m.sys.SendFrame(leaf.MACsec.Parent, frame)
			}
		}
	}()
	err = m.sys.RecvFrames(leaf.MACsec.Parent, macsecCtlAckWait, func(reply []byte) bool {
		cmd, _, echoed, ok := parseMACsecCtlFrame(reply, keys)
		return ok && cmd == macsecCtlAck && bytes.Equal(echoed, challenge)
	})
	return true, err
}
