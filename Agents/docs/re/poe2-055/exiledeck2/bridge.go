package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// bridgeResponse is one JSON answer line from the Gateway command bridge
// (Program.CommandBridge.cs: Game_CMD_PORT, default 7010).
type bridgeResponse struct {
	OK         bool     `json:"ok"`
	Ran        bool     `json:"ran"`
	Character  string   `json:"character"`
	Characters []string `json:"characters"`
	Error      string   `json:"error"`
}

// bridgeRoundTrip sends one line to the bridge and reads its one JSON answer line.
func bridgeRoundTrip(addr, line string) (*bridgeResponse, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintln(conn, line); err != nil {
		return nil, err
	}
	text, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && text == "" {
		return nil, err
	}
	var resp bridgeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &resp); err != nil {
		return nil, fmt.Errorf("桥的回应不是 JSON: %s", strings.TrimSpace(text))
	}
	return &resp, nil
}

// bridgeWho asks who is in the world; an error means the bridge (Gateway) is not reachable.
func bridgeWho(addr string) ([]string, error) {
	resp, err := bridgeRoundTrip(addr, `{"op":"who"}`)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Characters, nil
}

// bridgeCommand runs one slash command on the live connection via the bridge.
func bridgeCommand(addr, command string) (*bridgeResponse, error) {
	return bridgeRoundTrip(addr, command)
}
