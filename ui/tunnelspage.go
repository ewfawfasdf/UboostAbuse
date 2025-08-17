/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows/conf"
)

const mailAPI = "https://api.mail.tm"

type mailDomainResp []struct {
	Domain string `json:"domain"`
}

type mailTokenResp struct {
	Token string `json:"token"`
}

type mailMessagesResp []struct {
	ID string `json:"id"`
}

type mailMessage struct {
	Text string `json:"text"`
}

func prepareRequest(method, url string, body io.Reader, deviceID string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "uboost-android/1.1.1.31")
	req.Header.Set("X-Device-Id", deviceID)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Charset", "UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Accept-Encoding", "gzip")
	return req, nil
}

func postJSON(client *http.Client, url string, data interface{}, result interface{}, deviceID string) error {
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(data); err != nil {
		log.Printf("[err] Error encoding JSON for URL %s: %v", url, err)
		return err
	}
	req, err := prepareRequest("POST", url, buf, deviceID)
	if err != nil {
		return fmt.Errorf("error preparing POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[err] HTTP POST request error to URL %s: %v", url, err)
		return err
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	contentEncoding := resp.Header.Get("Content-Encoding")
	if strings.Contains(contentEncoding, "gzip") {
		gzReader, gzipErr := gzip.NewReader(resp.Body)
		if gzipErr != nil {
			log.Printf("[err] Error creating gzip reader for URL %s: %v", url, gzipErr)
			return fmt.Errorf("gzip decompression error: %w", gzipErr)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	bodyBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Printf("[err] Error reading response body for URL %s: %v", url, err)
		return fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode >= 300 {
		log.Printf("[err] HTTP POST request to URL %s returned status %d, response body: %s", url, resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	if result != nil {
		if err := json.Unmarshal(bodyBytes, result); err != nil {
			log.Printf("[err] Error decoding JSON result for URL %s: %v. Raw body: %s", url, err, string(bodyBytes))
			return err
		}
	}
	log.Printf("[+] Successful HTTP POST request to URL %s.", url)
	return nil
}

func createTempEmail(client *http.Client, deviceID string) (string, string, error) {
	log.Printf("[+] Requesting temporary email domains.")
	req, err := prepareRequest("GET", mailAPI+"/domains", nil, deviceID)
	if err != nil {
		return "", "", fmt.Errorf("error preparing domain request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error requesting domains: %w", err)
	}
	defer resp.Body.Close()

	var dom mailDomainResp
	if err := json.NewDecoder(resp.Body).Decode(&dom); err != nil {
		return "", "", fmt.Errorf("error decoding domain response: %w", err)
	}
	if len(dom) == 0 {
		return "", "", fmt.Errorf("no available domains")
	}

	email := fmt.Sprintf("%s@%s", hex.EncodeToString(randomBytes(5)), dom[0].Domain)
	pass := "password123"

	log.Printf("[+] Creating temporary email account: %s", email)
	accData := map[string]string{"address": email, "password": pass}
	if err := postJSON(client, mailAPI+"/accounts", accData, nil, deviceID); err != nil {
		return "", "", fmt.Errorf("error creating account: %w", err)
	}

	var tokenResp mailTokenResp
	log.Printf("[+] Requesting token for account: %s", email)
	if err := postJSON(client, mailAPI+"/token", accData, &tokenResp, deviceID); err != nil {
		return "", "", fmt.Errorf("error requesting token: %w", err)
	}
	log.Printf("[+] Token obtained.")
	return email, tokenResp.Token, nil
}

func requestEmailVerification(client *http.Client, email, deviceID string) error {
	url := fmt.Sprintf("https://api.ubstv.click/api/v1/auth/request_email_verification/?reason=mobile_request&email=%s", email)
	req, err := prepareRequest("GET", url, nil, deviceID)
	if err != nil {
		return fmt.Errorf("error preparing email verification request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[err] Error in HTTP GET request for email verification to URL %s: %v", url, err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		log.Printf("[err] HTTP GET request for email verification to URL %s returned status %d, response body: %s", url, resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("email verification request failed: status %d", resp.StatusCode)
	}
	log.Printf("[+] Email verification request successfully sent for: %s", email)
	return nil
}

func getLatestCode(client *http.Client, token, deviceID string) (string, error) {
	log.Printf("[+] Starting to wait for verification code.")
	for i := 0; i < 30; i++ {
		req, err := prepareRequest("GET", mailAPI+"/messages", nil, deviceID)
		if err != nil {
			return "", fmt.Errorf("error preparing messages request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[err] Error requesting messages: %v", err)
			return "", err
		}
		var msgs mailMessagesResp
		if err := json.NewDecoder(resp.Body).Decode(&msgs); err != nil {
			resp.Body.Close()
			log.Printf("[err] Error decoding messages: %v", err)
			return "", fmt.Errorf("error decoding messages: %w", err)
		}
		resp.Body.Close()

		if len(msgs) > 0 {
			log.Printf("[+] Messages found, getting latest message with ID: %s", msgs[0].ID)
			req2, err := prepareRequest("GET", mailAPI+"/messages/"+msgs[0].ID, nil, deviceID)
			if err != nil {
				return "", fmt.Errorf("error preparing specific message request: %w", err)
			}
			req2.Header.Set("Authorization", "Bearer "+token)
			resp2, err := client.Do(req2)
			if err != nil {
				log.Printf("[err] Error requesting specific message: %v", err)
				return "", err
			}
			var msg mailMessage
			if err := json.NewDecoder(resp2.Body).Decode(&msg); err != nil {
				resp2.Body.Close()
				log.Printf("[err] Error decoding message: %v", err)
				return "", fmt.Errorf("error decoding message: %w", err)
			}
			resp2.Body.Close()

			re := regexp.MustCompile(`\b\d{4}\b`)
			if match := re.FindString(msg.Text); match != "" {
				log.Printf("[+] Code received: %s", match)
				return match, nil
			}
		}
		log.Printf("Code not found, attempt %d of 30. Waiting 2 seconds.", i+1)
		time.Sleep(2 * time.Second)
	}
	log.Printf("[err] Verification code timed out.")
	return "", fmt.Errorf("code not received")
}

func submitMobileRequest(client *http.Client, email, otp string, deviceID string) (string, error) {
	data := map[string]string{"email": email, "otp_code": otp}
	var respData struct {
		Data struct {
			Request struct {
				PublicRequestID string `json:"public_request_id"`
			} `json:"request"`
		} `json:"data"`
	}
	log.Printf("[+] Submitting mobile request for email: %s", email)
	if err := postJSON(client, "https://api.ubstv.click/api/v1/mobile_request/", data, &respData, deviceID); err != nil {
		log.Printf("[err] Error submitting mobile request: %v", err)
		return "", err
	}
	if respData.Data.Request.PublicRequestID == "" {
		log.Printf("[err] No public_request_id received in mobile request response.")
		return "", fmt.Errorf("public_request_id not received")
	}
	log.Printf("[+] Mobile request sent, request ID: %s", respData.Data.Request.PublicRequestID)
	return respData.Data.Request.PublicRequestID, nil
}

func downloadMobileRequestKey(client *http.Client, reqID string, deviceID string) (string, error) {
	url := fmt.Sprintf("https://api.ubstv.click/api/v1/wg_keys/download_mobile_request_key?type_key=uboost_vpn&public_request_id=%s", reqID)
	log.Printf("[+] Starting key download for public_request_id: %s", reqID)
	for i := 0; i < 10; i++ {
		req, err := prepareRequest("GET", url, nil, deviceID)
		if err != nil {
			return "", fmt.Errorf("error preparing key request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[err] Error in HTTP GET request for key to URL %s (attempt %d): %v", url, i+1, err)
			return "", err
		}

		var reader io.Reader = resp.Body
		contentEncoding := resp.Header.Get("Content-Encoding")
		if strings.Contains(contentEncoding, "gzip") {
			gzReader, gzipErr := gzip.NewReader(resp.Body)
			if gzipErr != nil {
				log.Printf("[err] Error creating gzip reader for URL %s: %v", url, gzipErr)
				return "", fmt.Errorf("gzip decompression error: %w", gzipErr)
			}
			defer gzReader.Close()
			reader = gzReader
		}

		bodyBytes, _ := ioutil.ReadAll(reader)
		resp.Body.Close()

		if resp.StatusCode == 200 && len(strings.TrimSpace(string(bodyBytes))) > 0 {
			log.Printf("[+] Key successfully downloaded (attempt %d).", i+1)
			return string(bodyBytes), nil
		}
		log.Printf("Key not ready or empty response (attempt %d), status: %d. Waiting 2 seconds.", i+1, resp.StatusCode)
		time.Sleep(2 * time.Second)
	}
	log.Printf("[err] Key not received after 10 attempts for public_request_id: %s", reqID)
	return "", fmt.Errorf("key not ready")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

type TunnelsPage struct {
	*walk.TabPage

	listView      *ListView
	listContainer walk.Container
	listToolbar   *walk.ToolBar
	confView      *ConfView
	fillerButton  *walk.PushButton
	fillerHandler func()

	fillerContainer        *walk.Composite
	currentTunnelContainer *walk.Composite
}

func NewTunnelsPage() (*TunnelsPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	tp := new(TunnelsPage)
	if tp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(tp)

	tp.SetTitle(l18n.Sprintf("Tunnels"))
	hlayout := walk.NewHBoxLayout()
	hlayout.SetAlignment(walk.AlignHNearVCenter)
	tp.SetLayout(hlayout)

	tp.listContainer, _ = walk.NewComposite(tp)
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{})
	vlayout.SetSpacing(0)
	tp.listContainer.SetLayout(vlayout)

	if tp.listView, err = NewListView(tp.listContainer); err != nil {
		return nil, err
	}

	if tp.currentTunnelContainer, err = walk.NewComposite(tp); err != nil {
		return nil, err
	}
	vlayout = walk.NewVBoxLayout()
	vlayout.SetAlignment(walk.AlignHNearVCenter)
	vlayout.SetMargins(walk.Margins{})
	tp.currentTunnelContainer.SetLayout(vlayout)
	hlayout.SetStretchFactor(tp.currentTunnelContainer, 100)

	if tp.fillerContainer, err = walk.NewComposite(tp); err != nil {
		return nil, err
	}
	tp.fillerContainer.SetVisible(false)
	vlayout = walk.NewVBoxLayout()
	vlayout.SetAlignment(walk.AlignHCenterVCenter)
	vlayout.SetMargins(walk.Margins{})
	tp.fillerContainer.SetLayout(vlayout)
	hlayout.SetStretchFactor(tp.fillerContainer, 100)

	fillerButtonContainer, _ := walk.NewComposite(tp.fillerContainer)
	hlayout = walk.NewHBoxLayout()
	hlayout.SetMargins(walk.Margins{0, 40, 0, 25})
	fillerButtonContainer.SetLayout(hlayout)

	tp.fillerButton, _ = walk.NewPushButton(fillerButtonContainer)
	tp.fillerButton.SetMinMaxSize(walk.Size{200, 0}, walk.Size{200, 0})
	tp.fillerButton.SetVisible(IsAdmin)
	tp.fillerButton.Clicked().Attach(func() {
		if tp.fillerHandler != nil {
			tp.fillerHandler()
		}
	})

	fillerInfoContainer, err := walk.NewComposite(tp.fillerContainer)
	if err != nil {
		return nil, err
	}
	vlayout = walk.NewVBoxLayout()
	vlayout.SetAlignment(walk.AlignHCenterVCenter)
	vlayout.SetMargins(walk.Margins{})
	fillerInfoContainer.SetLayout(vlayout)

	fillerInfoLabel1, err := walk.NewLabel(fillerInfoContainer)
	if err != nil {
		return nil, err
	}
	fillerInfoLabel1.SetTextAlignment(walk.AlignCenter)
	fillerInfoLabel1.SetText(l18n.Sprintf("Ensure that you obtained the configuration file from a trusted source."))

	fillerInfoLabel2, err := walk.NewLabel(fillerInfoContainer)
	if err != nil {
		return nil, err
	}
	fillerInfoLabel2.SetTextAlignment(walk.AlignCenter)
	fillerInfoLabel2.SetText(l18n.Sprintf("Official Amnezia services are available only at amnezia.org."))

	if tp.confView, err = NewConfView(tp.currentTunnelContainer); err != nil {
		return nil, err
	}

	walk.NewVSpacer(tp.currentTunnelContainer)

	infoContainer, err := walk.NewComposite(tp.currentTunnelContainer)
	if err != nil {
		return nil, err
	}
	vlayout = walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{15, 0, 15, 0})
	infoContainer.SetLayout(vlayout)

	infoLabel, err := walk.NewLabel(infoContainer)
	if err != nil {
		return nil, err
	}
	infoLabel.SetText(l18n.Sprintf("Ensure that you obtained the configuration file from a trusted source."))
	infoLabel2, err := walk.NewLabel(infoContainer)
	if err != nil {
		return nil, err
	}
	infoLabel2.SetText(l18n.Sprintf("Official Amnezia services are available only at amnezia.org."))

	controlsContainer, err := walk.NewComposite(tp.currentTunnelContainer)
	if err != nil {
		return nil, err
	}
	hlayout = walk.NewHBoxLayout()
	hlayout.SetMargins(walk.Margins{})
	controlsContainer.SetLayout(hlayout)

	walk.NewHSpacer(controlsContainer)

	editTunnel, err := walk.NewPushButton(controlsContainer)
	if err != nil {
		return nil, err
	}
	editTunnel.SetEnabled(false)
	tp.listView.CurrentIndexChanged().Attach(func() {
		editTunnel.SetEnabled(tp.listView.CurrentIndex() > -1)
	})
	editTunnel.SetText(l18n.Sprintf("&Edit"))
	editTunnel.Clicked().Attach(tp.onEditTunnel)
	editTunnel.SetVisible(IsAdmin)

	disposables.Spare()

	tp.listView.ItemCountChanged().Attach(tp.onTunnelsChanged)
	tp.listView.SelectedIndexesChanged().Attach(tp.onSelectedTunnelsChanged)
	tp.listView.ItemActivated().Attach(tp.onTunnelsViewItemActivated)
	tp.listView.CurrentIndexChanged().Attach(tp.updateConfView)
	tp.listView.Load(false)
	tp.onTunnelsChanged()

	return tp, nil
}
func (tp *TunnelsPage) onExportTunnels() {
	dlg := walk.FileDialog{
		Filter: l18n.Sprintf("Configuration ZIP Files (*.zip)|*.zip"),
		Title:  l18n.Sprintf("Export tunnels to zip"),
	}

	if ok, _ := dlg.ShowSave(tp.Form()); !ok {
		return
	}

	if !strings.HasSuffix(dlg.FilePath, ".zip") {
		dlg.FilePath += ".zip"
	}

	tp.exportTunnels(dlg.FilePath)
}
func (tp *TunnelsPage) CreateToolbar() error {
	if tp.listToolbar != nil {
		return nil
	}

	toolBarContainer, err := walk.NewComposite(tp.listContainer)
	if err != nil {
		return err
	}
	toolBarContainer.SetDoubleBuffering(true)
	hlayout := walk.NewHBoxLayout()
	hlayout.SetMargins(walk.Margins{})
	toolBarContainer.SetLayout(hlayout)
	toolBarContainer.SetVisible(IsAdmin)

	if tp.listToolbar, err = walk.NewToolBarWithOrientationAndButtonStyle(toolBarContainer, walk.Horizontal, walk.ToolBarButtonImageBeforeText); err != nil {
		return err
	}

	addMenu, err := walk.NewMenu()
	if err != nil {
		return err
	}
	tp.AddDisposable(addMenu)
	importAction := walk.NewAction()
	importAction.SetText(l18n.Sprintf("&Import tunnel(s) from file…"))
	importActionIcon, _ := loadSystemIcon("imageres", -3, 16)
	importAction.SetImage(importActionIcon)
	importAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyO})
	importAction.SetDefault(true)
	importAction.Triggered().Attach(tp.onImport)
	addMenu.Actions().Add(importAction)
	addAction := walk.NewAction()
	addAction.SetText(l18n.Sprintf("Add &empty tunnel…"))
	addActionIcon, _ := loadSystemIcon("imageres", -2, 16)
	addAction.SetImage(addActionIcon)
	addAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyN})
	addAction.Triggered().Attach(tp.onAddTunnel)
	addMenu.Actions().Add(addAction)
	addMenuAction := walk.NewMenuAction(addMenu)
	addMenuActionIcon, _ := loadSystemIcon("shell32", -258, 16)
	addMenuAction.SetImage(addMenuActionIcon)
	addMenuAction.SetText(l18n.Sprintf("Add Tunnel"))
	addMenuAction.SetToolTip(importAction.Text())
	addMenuAction.Triggered().Attach(tp.onImport)
	tp.listToolbar.Actions().Add(addMenuAction)

	tp.listToolbar.Actions().Add(walk.NewSeparatorAction())

	deleteAction := walk.NewAction()
	deleteActionIcon, _ := loadSystemIcon("shell32", -240, 16)
	deleteAction.SetImage(deleteActionIcon)
	deleteAction.SetShortcut(walk.Shortcut{0, walk.KeyDelete})
	deleteAction.SetToolTip(l18n.Sprintf("Remove selected tunnel(s)"))
	deleteAction.Triggered().Attach(tp.onDelete)
	tp.listToolbar.Actions().Add(deleteAction)
	tp.listToolbar.Actions().Add(walk.NewSeparatorAction())

	exportAction := walk.NewAction()
	exportActionIcon, _ := loadSystemIcon("imageres", -174, 16)
	exportAction.SetImage(exportActionIcon)
	exportAction.SetToolTip(l18n.Sprintf("Export all tunnels to zip"))
	exportAction.Triggered().Attach(tp.onExportTunnels)
	tp.listToolbar.Actions().Add(exportAction)

	tp.listToolbar.Actions().Add(walk.NewSeparatorAction())
	abuseAction := walk.NewAction()
	abuseActionIcon, _ := loadSystemIcon("shell32", -16743, 16)
	abuseAction.SetImage(abuseActionIcon)
	abuseAction.SetText(l18n.Sprintf("Abuse Uboost"))
	abuseAction.SetToolTip(l18n.Sprintf("Generate abuse configuration"))
	abuseAction.Triggered().Attach(tp.onAbuseUboost)
	tp.listToolbar.Actions().Add(abuseAction)

	fixContainerWidthToToolbarWidth := func() {
		toolbarWidth := tp.listToolbar.SizeHint().Width
		tp.listContainer.SetMinMaxSizePixels(walk.Size{toolbarWidth, 0}, walk.Size{toolbarWidth, 0})
	}
	fixContainerWidthToToolbarWidth()
	tp.listToolbar.SizeChanged().Attach(fixContainerWidthToToolbarWidth)

	contextMenu, err := walk.NewMenu()
	if err != nil {
		return err
	}
	tp.listView.AddDisposable(contextMenu)
	toggleAction := walk.NewAction()
	toggleAction.SetText(l18n.Sprintf("&Toggle"))
	toggleAction.SetDefault(true)
	toggleAction.Triggered().Attach(tp.onTunnelsViewItemActivated)
	contextMenu.Actions().Add(toggleAction)
	contextMenu.Actions().Add(walk.NewSeparatorAction())
	importAction2 := walk.NewAction()
	importAction2.SetText(l18n.Sprintf("&Import tunnel(s) from file…"))
	importAction2.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyO})
	importAction2.Triggered().Attach(tp.onImport)
	importAction2.SetVisible(IsAdmin)
	contextMenu.Actions().Add(importAction2)
	tp.ShortcutActions().Add(importAction2)
	addAction2 := walk.NewAction()
	addAction2.SetText(l18n.Sprintf("Add &empty tunnel…"))
	addAction2.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyN})
	addAction2.Triggered().Attach(tp.onAddTunnel)
	addAction2.SetVisible(IsAdmin)
	contextMenu.Actions().Add(addAction2)
	tp.ShortcutActions().Add(addAction2)
	exportAction2 := walk.NewAction()
	exportAction2.SetText(l18n.Sprintf("Export all tunnels to &zip…"))
	exportAction2.Triggered().Attach(tp.onExportTunnels)
	exportAction2.SetVisible(IsAdmin)
	contextMenu.Actions().Add(exportAction2)
	contextMenu.Actions().Add(walk.NewSeparatorAction())
	editAction := walk.NewAction()
	editAction.SetText(l18n.Sprintf("Edit &selected tunnel…"))
	editAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyE})
	editAction.SetVisible(IsAdmin)
	editAction.Triggered().Attach(tp.onEditTunnel)
	contextMenu.Actions().Add(editAction)
	tp.ShortcutActions().Add(editAction)
	deleteAction2 := walk.NewAction()
	deleteAction2.SetText(l18n.Sprintf("&Remove selected tunnel(s)"))
	deleteAction2.SetShortcut(walk.Shortcut{0, walk.KeyDelete})
	deleteAction2.SetVisible(IsAdmin)
	deleteAction2.Triggered().Attach(tp.onDelete)
	contextMenu.Actions().Add(deleteAction2)
	tp.listView.ShortcutActions().Add(deleteAction2)
	selectAllAction := walk.NewAction()
	selectAllAction.SetText(l18n.Sprintf("Select &all"))
	selectAllAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyA})
	selectAllAction.SetVisible(IsAdmin)
	selectAllAction.Triggered().Attach(tp.onSelectAll)
	contextMenu.Actions().Add(selectAllAction)
	tp.listView.ShortcutActions().Add(selectAllAction)
	tp.listView.SetContextMenu(contextMenu)

	setSelectionOrientedOptions := func() {
		selected := len(tp.listView.SelectedIndexes())
		all := len(tp.listView.model.tunnels)
		deleteAction.SetEnabled(selected > 0)
		deleteAction2.SetEnabled(selected > 0)
		toggleAction.SetEnabled(selected == 1)
		selectAllAction.SetEnabled(selected < all)
		editAction.SetEnabled(selected == 1)
	}
	tp.listView.SelectedIndexesChanged().Attach(setSelectionOrientedOptions)
	setSelectionOrientedOptions()
	setExport := func() {
		all := len(tp.listView.model.tunnels)
		exportAction.SetEnabled(all > 0)
		exportAction2.SetEnabled(all > 0)
	}
	setExportRange := func(from, to int) { setExport() }
	tp.listView.model.RowsInserted().Attach(setExportRange)
	tp.listView.model.RowsRemoved().Attach(setExportRange)
	tp.listView.model.RowsReset().Attach(setExport)
	setExport()

	return nil
}

func (tp *TunnelsPage) updateConfView() {
	tp.confView.SetTunnel(tp.listView.CurrentTunnel())
}

func (tp *TunnelsPage) importFiles(paths []string) {
	go func() {
		syncedMsgBox := func(title, message string, flags walk.MsgBoxStyle) {
			tp.Synchronize(func() {
				walk.MsgBox(tp.Form(), title, message, flags)
			})
		}
		type unparsedConfig struct {
			Name   string
			Config string
		}

		var (
			unparsedConfigs []unparsedConfig
			lastErr         error
		)

		for _, path := range paths {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".conf":
				textConfig, err := os.ReadFile(path)
				if err != nil {
					lastErr = err
					continue
				}
				unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), Config: string(textConfig)})
			case ".zip":
				r, err := zip.OpenReader(path)
				if err != nil {
					lastErr = err
					continue
				}

				for _, f := range r.File {
					if strings.ToLower(filepath.Ext(f.Name)) != ".conf" {
						continue
					}

					rc, err := f.Open()
					if err != nil {
						lastErr = err
						continue
					}
					textConfig, err := io.ReadAll(rc)
					rc.Close()
					if err != nil {
						lastErr = err
						continue
					}
					unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name)), Config: string(textConfig)})
				}

				r.Close()
			}
		}

		if lastErr != nil || unparsedConfigs == nil {
			if lastErr == nil {
				lastErr = errors.New(l18n.Sprintf("no configuration files were found"))
			}
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Could not import selected configuration: %v", lastErr), walk.MsgBoxIconWarning)
			return
		}

		sort.Slice(unparsedConfigs, func(i, j int) bool {
			return conf.TunnelNameIsLess(unparsedConfigs[j].Name, unparsedConfigs[i].Name)
		})

		existingTunnelList, err := manager.IPCClientTunnels()
		if err != nil {
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Could not enumerate existing tunnels: %v", lastErr), walk.MsgBoxIconWarning)
			return
		}
		existingLowerTunnels := make(map[string]bool, len(existingTunnelList))
		for _, tunnel := range existingTunnelList {
			existingLowerTunnels[strings.ToLower(tunnel.Name)] = true
		}

		configCount := 0
		tp.listView.SetSuspendTunnelsUpdate(true)
		for _, unparsedConfig := range unparsedConfigs {
			if existingLowerTunnels[strings.ToLower(unparsedConfig.Name)] {
				lastErr = errors.New(l18n.Sprintf("Another tunnel already exists with the name ‘%s’", unparsedConfig.Name))
				continue
			}
			config, err := conf.FromWgQuickWithUnknownEncoding(unparsedConfig.Config, unparsedConfig.Name)
			if err != nil {
				lastErr = err
				continue
			}
			_, err = manager.IPCClientNewTunnel(config)
			if err != nil {
				lastErr = err
				continue
			}
			configCount++
		}
		tp.listView.SetSuspendTunnelsUpdate(false)

		m, n := configCount, len(unparsedConfigs)
		switch {
		case n == 1 && m != n:
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Unable to import configuration: %v", lastErr), walk.MsgBoxIconWarning)
		case n == 1 && m == n:
		case m == n:
			syncedMsgBox(l18n.Sprintf("Imported tunnels"), l18n.Sprintf("Imported %d tunnels", m), walk.MsgBoxIconInformation)
		case m != n:
			syncedMsgBox(l18n.Sprintf("Imported tunnels"), l18n.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
		}
	}()
}

func (tp *TunnelsPage) exportTunnels(filePath string) {
	writeFileWithOverwriteHandling(tp.Form(), filePath, func(file *os.File) error {
		writer := zip.NewWriter(file)

		for _, tunnel := range tp.listView.model.tunnels {
			cfg, err := tunnel.StoredConfig()
			if err != nil {
				return fmt.Errorf("onExportTunnels: tunnel.StoredConfig failed: %w", err)
			}

			w, err := writer.Create(tunnel.Name + ".conf")
			if err != nil {
				return fmt.Errorf("onExportTunnels: writer.Create failed: %w", err)
			}

			if _, err := w.Write(([]byte)(cfg.ToWgQuick())); err != nil {
				return fmt.Errorf("onExportTunnels: cfg.ToWgQuick failed: %w", err)
			}
		}

		return writer.Close()
	})
}

func (tp *TunnelsPage) addTunnel(config *conf.Config) {
	_, err := manager.IPCClientNewTunnel(config)
	if err != nil {
		showErrorCustom(tp.Form(), l18n.Sprintf("Unable to create tunnel"), err.Error())
	}
}

func (tp *TunnelsPage) swapFiller(enabled bool) bool {
	if tp.fillerContainer.Visible() == enabled {
		return enabled
	}
	tp.SetSuspended(true)
	tp.fillerContainer.SetVisible(enabled)
	tp.currentTunnelContainer.SetVisible(!enabled)
	tp.SetSuspended(false)
	return enabled
}

func (tp *TunnelsPage) onTunnelsChanged() {
	if tp.swapFiller(tp.listView.model.RowCount() == 0) {
		tp.fillerButton.SetText(l18n.Sprintf("Import tunnel(s) from file"))
		tp.fillerHandler = tp.onImport
	}
}

func (tp *TunnelsPage) onSelectedTunnelsChanged() {
	if tp.listView.model.RowCount() == 0 {
		return
	}
	indices := tp.listView.SelectedIndexes()
	tunnelCount := len(indices)
	if tp.swapFiller(tunnelCount > 1) {
		tp.fillerButton.SetText(l18n.Sprintf("Delete %d tunnels", tunnelCount))
		tp.fillerHandler = tp.onDelete
	}
}

func (tp *TunnelsPage) onTunnelsViewItemActivated() {
	go func() {
		globalState, err := manager.IPCClientGlobalState()
		if err != nil || (globalState != manager.TunnelStarted && globalState != manager.TunnelStopped) {
			return
		}
		oldState, err := tp.listView.CurrentTunnel().Toggle()
		if err != nil {
			tp.Synchronize(func() {
				if oldState == manager.TunnelUnknown {
					showErrorCustom(tp.Form(), l18n.Sprintf("Failed to determine tunnel state"), err.Error())
				} else if oldState == manager.TunnelStopped {
					showErrorCustom(tp.Form(), l18n.Sprintf("Failed to activate tunnel"), err.Error())
				} else if oldState == manager.TunnelStarted {
					showErrorCustom(tp.Form(), l18n.Sprintf("Failed to deactivate tunnel"), err.Error())
				}
			})
			return
		}
	}()
}

func (tp *TunnelsPage) onEditTunnel() {
	tunnel := tp.listView.CurrentTunnel()
	if tunnel == nil {
		return
	}

	if config := runEditDialog(tp.Form(), tunnel); config != nil {
		go func() {
			priorState, err := tunnel.State()
			tunnel.Delete()
			tunnel.WaitForStop()
			tunnel, err2 := manager.IPCClientNewTunnel(config)
			if err == nil && err2 == nil && (priorState == manager.TunnelStarting || priorState == manager.TunnelStarted) {
				tunnel.Start()
			}
		}()
	}
}

func (tp *TunnelsPage) onAddTunnel() {
	if config := runEditDialog(tp.Form(), nil); config != nil {
		tp.addTunnel(config)
	}
}

func (tp *TunnelsPage) onDelete() {
	indices := tp.listView.SelectedIndexes()
	if len(indices) == 0 {
		return
	}

	var title, question string
	if len(indices) > 1 {
		tunnelCount := len(indices)
		title = l18n.Sprintf("Delete %d tunnels", tunnelCount)
		question = l18n.Sprintf("Are you sure you would like to delete %d tunnels?", tunnelCount)
	} else {
		tunnelName := tp.listView.model.tunnels[indices[0]].Name
		title = l18n.Sprintf("Delete tunnel ‘%s’", tunnelName)
		question = l18n.Sprintf("Are you sure you would like to delete tunnel ‘%s’?", tunnelName)
	}
	if walk.DlgCmdNo == walk.MsgBox(
		tp.Form(),
		title,
		l18n.Sprintf("%s You cannot undo this action.", question),
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return
	}

	selectTunnelAfter := ""
	if len(indices) < len(tp.listView.model.tunnels) {
		sort.Ints(indices)
		max := 0
		for i, idx := range indices {
			if idx+1 < len(tp.listView.model.tunnels) && (i+1 == len(indices) || idx+1 != indices[i+1]) {
				max = idx + 1
			} else if idx-1 >= 0 && (i == 0 || idx-1 != indices[i-1]) {
				max = idx - 1
			}
		}
		selectTunnelAfter = tp.listView.model.tunnels[max].Name
	}
	if len(selectTunnelAfter) > 0 {
		tp.listView.selectTunnel(selectTunnelAfter)
	}

	tunnelsToDelete := make([]manager.Tunnel, len(indices))
	for i, j := range indices {
		tunnelsToDelete[i] = tp.listView.model.tunnels[j]
	}
	go func() {
		tp.listView.SetSuspendTunnelsUpdate(true)
		var errors []error
		for _, tunnel := range tunnelsToDelete {
			err := tunnel.Delete()
			if err != nil && (len(errors) == 0 || errors[len(errors)-1].Error() != err.Error()) {
				errors = append(errors, err)
			}
		}
		tp.listView.SetSuspendTunnelsUpdate(false)
		if len(errors) > 0 {
			tp.listView.Synchronize(func() {
				if len(errors) == 1 {
					showErrorCustom(tp.Form(), l18n.Sprintf("Unable to delete tunnel"), l18n.Sprintf("A tunnel was unable to be removed: %s", errors[0].Error()))
				} else {
					showErrorCustom(tp.Form(), l18n.Sprintf("Unable to delete tunnels"), l18n.Sprintf("%d tunnels were unable to be removed.", len(errors)))
				}
			})
		}
	}()
}

func (tp *TunnelsPage) onSelectAll() {
	tp.listView.SetSelectedIndexes([]int{-1})
}

func (tp *TunnelsPage) onImport() {
	dlg := walk.FileDialog{
		Filter: l18n.Sprintf("Configuration Files (*.zip, *.conf)|*.zip;*.conf|All Files (*.*)|*.*"),
		Title:  l18n.Sprintf("Import tunnel(s) from file"),
	}

	if ok, _ := dlg.ShowOpenMultiple(tp.Form()); !ok {
		return
	}

	tp.importFiles(dlg.FilePaths)
}

func (tp *TunnelsPage) onAbuseUboost() {
	go func() {
		deviceID := uuid.New().String()

		client := &http.Client{Timeout: 15 * time.Second}

		log.Printf("Starting Abuse Uboost process (Device ID: %s).", deviceID)
		tp.Synchronize(func() {
			walk.MsgBox(tp.Form(), l18n.Sprintf("Генерация Abuse Uboost"), l18n.Sprintf("Начинается генерация конфигурации Uboost..."), walk.MsgBoxIconInformation)
		})

		email, token, err := createTempEmail(client, deviceID)
		if err != nil {
			log.Printf("Error creating temporary email: %v", err)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", err.Error())
			})
			return
		}
		log.Printf("Temporary email created: %s", email)

		if err := requestEmailVerification(client, email, deviceID); err != nil {
			log.Printf("Error requesting email verification: %v", err)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", err.Error())
			})
			return
		}
		log.Printf("Email verification request sent for: %s", email)

		code, err := getLatestCode(client, token, deviceID)
		if err != nil {
			log.Printf("Error getting verification code: %v", err)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", err.Error())
			})
			return
		}
		log.Printf("Verification code received: %s", code)

		reqID, err := submitMobileRequest(client, email, code, deviceID)
		if err != nil {
			log.Printf("Error submitting mobile request: %v", err)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", err.Error())
			})
			return
		}
		log.Printf("Mobile request sent, request ID: %s", reqID)

		key, err := downloadMobileRequestKey(client, reqID, deviceID)
		if err != nil {
			log.Printf("Error downloading configuration: %v", err)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", err.Error())
			})
			return
		}
		log.Printf("Configuration successfully downloaded.")

		key = strings.TrimLeft(key, " ")
		rePeer := regexp.MustCompile(`(\[Interface\][^\[]+)(\[Peer\])`)
		key = rePeer.ReplaceAllString(key, "${1}\n\n${2}")

		cfg, cfgErr := conf.FromWgQuick(key, "AbuseConfig")
		if cfgErr != nil {
			log.Printf("Error parsing WireGuard configuration: %v", cfgErr)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", cfgErr.Error())
			})
			return
		}
		if _, err := manager.IPCClientNewTunnel(cfg); err != nil {
			log.Printf("Error creating new IPC tunnel: %v", err)
			tp.Synchronize(func() {
				showErrorCustom(tp.Form(), "Error", err.Error())
			})
			return
		}
		log.Printf("Tunnel 'AbuseConfig' successfully imported.")
		tp.Synchronize(func() {
			walk.MsgBox(tp.Form(), l18n.Sprintf("Генерация Abuse Uboost"), l18n.Sprintf("Конфигурация Uboost успешно импортирована!"), walk.MsgBoxIconInformation)
		})
	}()
}

// func NewListView(parent walk.Container) (*ListView, error) { }
// func NewConfView(parent walk.Container) (*ConfView, error) { }
// var IsAdmin bool
// func loadSystemIcon(library string, index int, size int) (*walk.Icon, error) { }
// func runEditDialog(owner walk.Form, tunnel *manager.Tunnel) *conf.Config { }
// func showErrorCustom(owner walk.Form, title, message string) { }
// func writeFileWithOverwriteHandling(owner walk.Form, filePath string, writer func(*os.File) error) { }
