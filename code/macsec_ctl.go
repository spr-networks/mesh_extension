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
	macsecCtlProbe        byte = 3
	macsecCtlProbeReply   byte = 4
	macsecCtlChallengeLen      = 16
	macsecCtlMACLen            = 32
	macsecCtlPayloadLen        = len(macsecCtlMagic) + 1 + macsecCKNLen + macsecCtlChallengeLen + 2 + macsecCtlMACLen
	macsecProbeWait            = time.Second
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

func macsecCtlTag(keys macsecCtlKeys, cmd byte, challenge []byte, total int) []byte {
	mac := hmac.New(sha256.New, keys.Key)
	mac.Write([]byte(macsecCtlMagic))
	mac.Write([]byte{cmd})
	mac.Write(keys.CKN)
	mac.Write(challenge)
	mac.Write(binary.BigEndian.AppendUint16(nil, uint16(total)))
	return mac.Sum(nil)
}

func newMACsecChallenge() ([]byte, error) {
	challenge := make([]byte, macsecCtlChallengeLen)
	_, err := rand.Read(challenge)
	return challenge, err
}

func buildMACsecCtlFrame(dst, src net.HardwareAddr, cmd byte, keys macsecCtlKeys, challenge []byte) []byte {
	return buildMACsecCtlFrameSized(dst, src, cmd, keys, challenge, macsecCtlFrameLen)
}

func buildMACsecCtlFrameSized(dst, src net.HardwareAddr, cmd byte, keys macsecCtlKeys, challenge []byte, total int) []byte {
	if len(dst) != 6 || len(src) != 6 {
		return nil
	}
	if total < macsecCtlFrameLen {
		total = macsecCtlFrameLen
	}
	frame := make([]byte, 0, total)
	frame = append(frame, dst...)
	frame = append(frame, src...)
	frame = binary.BigEndian.AppendUint16(frame, macsecCtlEtherType)
	frame = append(frame, macsecCtlMagic...)
	frame = append(frame, cmd)
	frame = append(frame, keys.CKN...)
	frame = append(frame, challenge...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(total))
	frame = append(frame, macsecCtlTag(keys, cmd, challenge, total)...)
	return append(frame, make([]byte, total-len(frame))...)
}

func parseMACsecCtlFrame(frame []byte, keys macsecCtlKeys) (cmd byte, src net.HardwareAddr, challenge []byte, ok bool) {
	cmd, src, challenge, _, ok = parseMACsecCtlFrameSized(frame, keys)
	return
}

func parseMACsecCtlFrameSized(frame []byte, keys macsecCtlKeys) (cmd byte, src net.HardwareAddr, challenge []byte, total int, ok bool) {
	if len(frame) < macsecCtlFrameLen || len(keys.CKN) != macsecCKNLen || len(keys.Key) == 0 {
		return 0, nil, nil, 0, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != macsecCtlEtherType {
		return 0, nil, nil, 0, false
	}
	p := frame[14:macsecCtlFrameLen]
	if string(p[:len(macsecCtlMagic)]) != macsecCtlMagic {
		return 0, nil, nil, 0, false
	}
	p = p[len(macsecCtlMagic):]
	cmd = p[0]
	ckn := p[1 : 1+macsecCKNLen]
	challenge = p[1+macsecCKNLen : 1+macsecCKNLen+macsecCtlChallengeLen]
	total = int(binary.BigEndian.Uint16(p[1+macsecCKNLen+macsecCtlChallengeLen:]))
	tag := p[1+macsecCKNLen+macsecCtlChallengeLen+2:]
	if total < macsecCtlFrameLen || len(frame) < total {
		return 0, nil, nil, 0, false
	}
	if !bytes.Equal(ckn, keys.CKN) {
		return 0, nil, nil, 0, false
	}
	if !hmac.Equal(tag, macsecCtlTag(keys, cmd, challenge, total)) {
		return 0, nil, nil, 0, false
	}
	src = append(net.HardwareAddr{}, frame[6:12]...)
	return cmd, src, append([]byte{}, challenge...), total, true
}

const macsecCtlAckWindow = 30 * time.Second

func (m *macsecManager) ctlMAC() net.HardwareAddr {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	return m.leafCtlMAC
}

func (m *macsecManager) ctlKeys() *macsecCtlKeys {
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
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
	cmd, src, challenge, total, ok := parseMACsecCtlFrameSized(frame, *keys)
	if !ok {
		return false
	}
	if cmd == macsecCtlProbe {
		if reply := buildMACsecCtlFrameSized(src, m.ctlMAC(), macsecCtlProbeReply, *keys, challenge, total); reply != nil {
			m.sys.SendFrame(wanif, reply)
		}
		return false
	}
	if cmd != macsecCtlDisable {
		return false
	}
	if ack := buildMACsecCtlFrame(src, m.ctlMAC(), macsecCtlAck, *keys, challenge); ack != nil {
		m.sys.SendFrame(wanif, ack)
	}
	m.ctlMu.Lock()
	first := m.ctlOffAt.IsZero()
	if first {
		m.ctlOffAt = m.now()
	}
	m.ctlMu.Unlock()
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

func (m *macsecManager) probeFrame(parent string, keys macsecCtlKeys, src, dst net.HardwareAddr, size int) (net.HardwareAddr, bool) {
	challenge, err := newMACsecChallenge()
	if err != nil {
		return nil, false
	}
	total := 14 + size
	frame := buildMACsecCtlFrameSized(dst, src, macsecCtlProbe, keys, challenge, total)
	var from net.HardwareAddr
	for attempt := 0; attempt < 2; attempt++ {
		err := m.sys.Exchange(parent, frame, macsecProbeWait, func(reply []byte) bool {
			cmd, s, echoed, t, ok := parseMACsecCtlFrameSized(reply, keys)
			if ok && cmd == macsecCtlProbeReply && t == total && bytes.Equal(echoed, challenge) {
				from = s
				return true
			}
			return false
		})
		if err == nil {
			return from, true
		}
	}
	return nil, false
}

var errMTUProbeNoReply = errors.New("mesh node did not answer the MTU test")

func (m *macsecManager) testUnderlayMTU(leaf LeafRouter) (int, error) {
	if leaf.MACsec == nil || !leaf.MACsec.Enabled {
		return 0, errors.New("encryption is not enabled for this mesh node")
	}
	keys, err := deriveMACsecCtlKeys(leaf.APIToken, leaf.MACsec.KeyNonce)
	if err != nil {
		return 0, err
	}
	info, err := m.sys.LinkInfo(leaf.MACsec.Parent)
	if err != nil {
		return 0, err
	}
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	nodeMAC, ok := m.probeFrame(leaf.MACsec.Parent, keys, info.MAC, broadcast, macsecEthernetMTU)
	if !ok {
		return 0, errMTUProbeNoReply
	}
	max := info.MTU
	if max > meshJumboMTU {
		max = meshJumboMTU
	}
	if max <= macsecEthernetMTU {
		return macsecEthernetMTU, nil
	}
	if _, ok := m.probeFrame(leaf.MACsec.Parent, keys, info.MAC, nodeMAC, max); ok {
		return max, nil
	}
	lo, hi := macsecEthernetMTU, max
	for hi-lo > 8 {
		mid := (lo + hi) / 2
		if _, ok := m.probeFrame(leaf.MACsec.Parent, keys, info.MAC, nodeMAC, mid); ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}
